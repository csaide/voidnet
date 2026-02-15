#[cfg(feature = "tokio")]
use std::{os::fd::RawFd, sync::Arc};

use crate::xdp::{
    error::Result,
    program::{AttachMode, Map, XdpInfo, XdpProgram},
    socket::SocketOwner,
};

/// Embedded XDP BPF program for round-robin packet routing to AF_XDP sockets.
static XDP_PROG_DATA: &'static [u8] = include_bytes!("../../../bpf/xdp_kern.o");

/// Builder for creating an XdpContext.
///
/// # Examples
///
/// ```no_run
/// use libvoid::xdp::context::XdpContext;
/// let ctx = XdpContext::builder("eth0").build();
/// ```
pub struct XdpContextBuilder<'name> {
    if_name: &'name str,
    attach_mode: AttachMode,
    enable_fragmentation: bool,
}

impl<'name> XdpContextBuilder<'name> {
    /// Creates a new XdpContextBuilder.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use libvoid::xdp::context::XdpContextBuilder;
    /// let builder = XdpContextBuilder::new("eth0");
    /// ```
    pub fn new(if_name: &'name str) -> Self {
        Self {
            if_name,
            attach_mode: AttachMode::default(),
            enable_fragmentation: false,
        }
    }

    /// Sets the attach mode for the XDP program.
    pub fn attach_mode(mut self, attach_mode: AttachMode) -> Self {
        self.attach_mode = attach_mode;
        self
    }

    /// Enables or disables fragmentation for the XDP program.
    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.enable_fragmentation = enable_fragmentation;
        self
    }

    /// Builds the XdpContext.
    pub fn build(self) -> Result<XdpContext> {
        XdpContext::new(&self.if_name, self.attach_mode, self.enable_fragmentation)
    }
}

/// Manages the XDP program lifecycle and socket registration.
///
/// See the [module documentation](crate::xdp::context) for usage examples.
///
/// # Socket Registration
///
/// Sockets are registered via [`Socket::builder`](crate::xdp::socket::Socket::builder),
/// which updates the BPF maps so the kernel can route packets using round-robin
/// distribution across registered sockets.
pub struct XdpContext {
    /// BPF map containing the `num_sockets` counter in the program's `.bss` section.
    data_map: Map,
    /// BPF map array storing socket file descriptors indexed by socket number.
    xsks_map: Map,
    /// Current count of registered sockets; used as the next index in `xsks_map`.
    num_sockets: u32,
    /// The loaded and attached XDP program.
    program: XdpProgram,
    #[cfg(feature = "tokio")]
    tokio_fd_factory: crate::xdp::futures::TokioFdFactory,
    #[cfg(feature = "smol")]
    smol_fd_factory: crate::xdp::futures::SmolFdFactory,
}

impl XdpContext {
    /// Returns a builder for creating an XdpContext.
    pub fn builder(if_name: &str) -> XdpContextBuilder<'_> {
        XdpContextBuilder::new(if_name)
    }

    fn new(if_name: &str, attach_mode: AttachMode, enable_fragmentation: bool) -> Result<Self> {
        let program = XdpProgram::new(XDP_PROG_DATA, if_name, attach_mode, enable_fragmentation)?;

        let data_map = program.find_map(".bss")?;
        let xsks_map = program.find_map("xsks_map")?;

        Ok(Self {
            data_map,
            xsks_map,
            num_sockets: 0,
            program,
            #[cfg(feature = "tokio")]
            tokio_fd_factory: crate::xdp::futures::TokioFdFactory::new(),
            #[cfg(feature = "smol")]
            smol_fd_factory: crate::xdp::futures::SmolFdFactory::new(),
        })
    }

    #[cfg(test)]
    pub fn new_no_init() -> Result<Self> {
        Ok(Self {
            data_map: Map::new(std::ptr::null_mut(), unsafe { std::mem::zeroed() }),
            xsks_map: Map::new(std::ptr::null_mut(), unsafe { std::mem::zeroed() }),
            num_sockets: 0,
            program: XdpProgram::new_no_init()?,
            #[cfg(feature = "tokio")]
            tokio_fd_factory: crate::xdp::futures::TokioFdFactory::new(),
            #[cfg(feature = "smol")]
            smol_fd_factory: crate::xdp::futures::SmolFdFactory::new(),
        })
    }

    /// Returns the actual attach mode used (may differ from requested if `Unspec` was used).
    pub fn attach_mode(&self) -> AttachMode {
        self.program.attach_mode()
    }

    /// Returns interface capabilities (MTU, zero-copy support, fragmentation, etc.).
    pub fn info(&self) -> &XdpInfo {
        self.program.info()
    }

    pub(crate) fn register_socket(&mut self, socket: &mut SocketOwner<'_>) -> Result<()> {
        let loc = self.num_sockets;
        self.num_sockets += 1;

        // Update our xsks_map with the socket's file descriptor.
        // SAFETY: The map was created with u32 keys and i32 (fd) values.
        // The `loc` index is valid as it's derived from our internal counter.
        unsafe { self.xsks_map.update_elem(&loc, &socket.fd())? };

        const KEY: u32 = 0;
        // Update our num_sockets counter in the XDP program's .bss map.
        // SAFETY: The .bss map contains a u32 at key 0 by program design.
        unsafe { self.data_map.update_elem(&KEY, &self.num_sockets)? };

        Ok(())
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn get_tokio_fd(&self, fd: RawFd) -> Result<Arc<tokio::io::unix::AsyncFd<RawFd>>> {
        self.tokio_fd_factory.get_tokio_fd(fd)
    }

    #[cfg(feature = "smol")]
    pub(crate) fn get_smol_fd(
        &self,
        fd: RawFd,
    ) -> Result<Arc<async_io::Async<crate::xdp::futures::SmolFd>>> {
        self.smol_fd_factory.get_smol_fd(fd)
    }

    #[cfg(test)]
    pub(crate) fn num_sockets(&self) -> u32 {
        self.num_sockets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::test_utils::TestVethPair;

    /// Tests that XdpContext can be created with default attach mode and fragmentation enabled.
    #[test]
    fn test_context_creation() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let ctx = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .build();
        assert!(ctx.is_ok(), "failed to create XdpContext: {:?}", ctx.err());

        let ctx = ctx.unwrap();
        assert_eq!(ctx.num_sockets(), 0);
        assert_eq!(ctx.attach_mode(), AttachMode::default());

        let info = ctx.info();

        // The XDP program should have a non-zero program ID after attachment.
        // For veth devices using skb mode, the skb_prog_id should be set.
        assert!(
            info.prog_id > 0 || info.drv_prog_id > 0 || info.skb_prog_id > 0 || info.hw_prog_id > 0,
            "expected at least one prog_id to be set in XdpInfo"
        );

        // MTU should be set to a reasonable value (veth default is typically 1500).
        assert!(info.mtu > 0, "expected MTU to be set");

        assert!(
            info.basic_support(),
            "expected veth to support basic XDP features"
        );
    }

    /// Tests that creating a context with a non-existent interface fails.
    #[test]
    fn test_context_creation_nonexistent_interface() {
        let result = XdpContext::builder("nonexistent_iface_xyz123")
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .build();
        assert!(result.is_err(), "expected error for non-existent interface");
    }

    /// Tests that multiple contexts can be created on different veth pairs.
    #[test]
    fn test_multiple_contexts_different_interfaces() {
        let veth1 = TestVethPair::new().expect("failed to create first veth pair");
        let veth2 = TestVethPair::new().expect("failed to create second veth pair");

        let ctx1 = XdpContext::builder(veth1.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .build()
            .expect("context 1");
        let ctx2 = XdpContext::builder(veth2.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .build()
            .expect("context 2");

        // Both contexts should have their own state.
        assert_eq!(ctx1.num_sockets(), 0);
        assert_eq!(ctx2.num_sockets(), 0);

        // Their program IDs should be different.
        let info1 = ctx1.info();
        let info2 = ctx2.info();

        let prog_id_1 = info1.prog_id + info1.drv_prog_id + info1.skb_prog_id + info1.hw_prog_id;
        let prog_id_2 = info2.prog_id + info2.drv_prog_id + info2.skb_prog_id + info2.hw_prog_id;

        assert_ne!(
            prog_id_1, prog_id_2,
            "expected different program IDs for different interfaces"
        );
    }

    /// Tests that contexts can be created on both ends of a veth pair.
    #[test]
    fn test_context_on_both_veth_ends() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let ctx_outer = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .build()
            .expect("outer context");
        let ctx_inner = XdpContext::builder(veth.inner_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .build()
            .expect("inner context");

        // Both should be valid with separate state.
        assert_eq!(ctx_outer.num_sockets(), 0);
        assert_eq!(ctx_inner.num_sockets(), 0);

        // Their MTUs should match since they're a pair.
        assert_eq!(ctx_outer.info().mtu, ctx_inner.info().mtu);
    }
}
