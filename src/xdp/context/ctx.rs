use std::sync::Arc;

use crate::xdp::{
    error::Result,
    futures::Poller,
    program::{AttachMode, Map, XdpInfo, XdpProgram},
    socket::SocketOwner,
};

/// Embedded XDP BPF program for round-robin packet routing to AF_XDP sockets.
static XDP_PROG_DATA: &'static [u8] = include_bytes!("../../../bpf/xdp_kern.o");

pub struct XdpContextBuilder<'name> {
    if_name: &'name str,
    attach_mode: AttachMode,
    enable_fragmentation: bool,
    async_mode: bool,
    poller_max_events: usize,
    poller_timeout_ms: i32,
}

impl<'name> XdpContextBuilder<'name> {
    pub fn new(if_name: &'name str) -> Self {
        Self {
            if_name,
            attach_mode: AttachMode::default(),
            enable_fragmentation: false,
            async_mode: false,
            poller_max_events: 1024,
            poller_timeout_ms: 100,
        }
    }

    pub fn attach_mode(mut self, attach_mode: AttachMode) -> Self {
        self.attach_mode = attach_mode;
        self
    }

    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.enable_fragmentation = enable_fragmentation;
        self
    }

    pub fn async_mode(mut self, async_mode: bool) -> Self {
        self.async_mode = async_mode;
        self
    }

    pub fn poller_max_events(mut self, poller_max_events: usize) -> Self {
        self.poller_max_events = poller_max_events;
        self
    }

    pub fn poller_timeout_ms(mut self, poller_timeout_ms: i32) -> Self {
        self.poller_timeout_ms = poller_timeout_ms;
        self
    }

    pub fn build(self) -> Result<XdpContext> {
        XdpContext::new(
            &self.if_name,
            self.attach_mode,
            self.enable_fragmentation,
            self.async_mode,
            self.poller_max_events,
            self.poller_timeout_ms,
        )
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
    /// Enable async mode for the context.
    poller: Option<Arc<Poller>>,
}

impl XdpContext {
    pub fn builder(if_name: &str) -> XdpContextBuilder<'_> {
        XdpContextBuilder::new(if_name)
    }

    fn new(
        if_name: &str,
        attach_mode: AttachMode,
        enable_fragmentation: bool,
        async_mode: bool,
        poller_max_events: usize,
        poller_timeout_ms: i32,
    ) -> Result<Self> {
        let program = XdpProgram::new(XDP_PROG_DATA, if_name, attach_mode, enable_fragmentation)?;

        let data_map = program.find_map(".bss")?;
        let xsks_map = program.find_map("xsks_map")?;

        Ok(Self {
            data_map,
            xsks_map,
            num_sockets: 0,
            program,
            poller: if async_mode {
                let poller = Arc::new(Poller::new(poller_max_events, poller_timeout_ms).unwrap());
                std::thread::spawn({
                    let poller = poller.clone();
                    move || match poller.poll() {
                        Ok(_) => (),
                        Err(e) => eprintln!("Poller error: {}", e),
                    }
                });
                Some(poller)
            } else {
                None
            },
        })
    }

    #[cfg(test)]
    pub fn new_no_init() -> Result<Self> {
        Ok(Self {
            data_map: Map::new(std::ptr::null_mut(), unsafe { std::mem::zeroed() }),
            xsks_map: Map::new(std::ptr::null_mut(), unsafe { std::mem::zeroed() }),
            num_sockets: 0,
            program: XdpProgram::new_no_init()?,
            poller: None,
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

        if let Some(poller) = &self.poller {
            poller.register_socket(socket.fd())?;
        }
        Ok(())
    }

    pub(crate) fn get_poller(&self) -> Option<&Arc<Poller>> {
        self.poller.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn num_sockets(&self) -> u32 {
        self.num_sockets
    }
}

impl Drop for XdpContext {
    fn drop(&mut self) {
        if let Some(poller) = self.poller.take() {
            poller.exit();
        }
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
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
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
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
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
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("context 1");
        let ctx2 = XdpContext::builder(veth2.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
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
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("outer context");
        let ctx_inner = XdpContext::builder(veth.inner_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(true)
            .async_mode(false)
            .poller_max_events(1024)
            .poller_timeout_ms(100)
            .build()
            .expect("inner context");

        // Both should be valid with separate state.
        assert_eq!(ctx_outer.num_sockets(), 0);
        assert_eq!(ctx_inner.num_sockets(), 0);

        // Their MTUs should match since they're a pair.
        assert_eq!(ctx_outer.info().mtu, ctx_inner.info().mtu);
    }
}
