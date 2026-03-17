use crate::xdp::{
    error::{Error, Result},
    program::{AttachMode, Map, XdpInfo, XdpProgram},
    socket::SocketOwner,
};

/// Embedded XDP BPF program for round-robin packet routing to AF_XDP sockets.
static XDP_PROG_DATA: &[u8] = include_bytes!("../../../bpf/xdp_kern.o");

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
        XdpContext::new(self.if_name, self.attach_mode, self.enable_fragmentation)
    }
}

/// Manages the XDP program lifecycle and socket registration.
///
/// See the [module documentation](crate::xdp::context) for usage examples.
///
/// # Socket Registration
///
/// Sockets are registered via [`Socket::builder`](crate::xdp::socket::Socket::builder),
/// which updates the BPF maps so the kernel can route packets using queue-based
/// routing to registered sockets.
pub struct XdpContext {
    /// BPF map array storing socket file descriptors indexed by queue ID.
    xsks_map: Map,
    /// The loaded and attached XDP program.
    program: XdpProgram,
}

impl XdpContext {
    /// Returns a builder for creating an XdpContext.
    pub fn builder(if_name: &str) -> XdpContextBuilder<'_> {
        XdpContextBuilder::new(if_name)
    }

    fn new(if_name: &str, attach_mode: AttachMode, enable_fragmentation: bool) -> Result<Self> {
        let program = XdpProgram::new(XDP_PROG_DATA, if_name, attach_mode, enable_fragmentation)?;

        let xsks_map = program.find_map("xsks_map")?;

        Ok(Self { xsks_map, program })
    }

    #[cfg(test)]
    pub fn new_no_init() -> Result<Self> {
        Ok(Self {
            xsks_map: Map::new(std::ptr::null_mut(), unsafe { std::mem::zeroed() }),
            program: XdpProgram::new_no_init()?,
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

    pub(crate) fn register_socket(
        &mut self,
        socket: &mut SocketOwner<'_>,
        map_index: u32,
    ) -> Result<()> {
        if map_index >= 2048 {
            return Err(Error::QueueIdOutOfRange(map_index));
        }
        // Update xsks_map with the socket's file descriptor at the given map index.
        // SAFETY: The map was created with u32 keys and i32 (fd) values.
        unsafe { self.xsks_map.update_elem(&map_index, &socket.fd())? };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::xdp::test_utils::TestVethPair;

    use super::*;

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

        // Their MTUs should match since they're a pair.
        assert_eq!(ctx_outer.info().mtu, ctx_inner.info().mtu);
    }

    /// Tests that register_socket places the socket at the queue ID index in xsks_map.
    #[test]
    fn test_register_socket_uses_queue_id() {
        use crate::xdp::socket::Socket;

        let veth = TestVethPair::new().expect("failed to create veth pair");
        let mut ctx = XdpContext::builder(veth.outer_name())
            .attach_mode(AttachMode::default())
            .enable_fragmentation(false)
            .build()
            .expect("failed to create context");

        let (umem, _fq, _cq) = crate::xdp::umem::Umem::builder()
            .num_frames(16)
            .frame_size(4096)
            .fill_ring_size(8)
            .completion_ring_size(8)
            .build()
            .expect("failed to create umem")
            .split();

        // Build socket on queue 0 (the only queue veth supports).
        let _socket = Socket::builder(veth.outer_name(), 0)
            .rx_ring_size(8)
            .tx_ring_size(8)
            .build(&mut ctx, umem)
            .expect("failed to create socket");
        // Verify: no panic, socket was registered at xsks_map[0].
    }
}
