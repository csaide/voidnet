use crate::xdp::{
    error::Result,
    program::{AttachMode, Map, XdpInfo, XdpProgram},
};

// We ship our little XDP router directly embedded in this library as raw ELF data.
static XDP_PROG_DATA: &'static [u8] = include_bytes!("../../../bpf/xdp_kern.o");

/// A context wraps up the XDP program and its associated state and maps. This is the primary entrypoint into the XDP subsystem.
pub struct XdpContext {
    data_map: Map,
    xsks_map: Map,
    num_sockets: u32,
    program: XdpProgram,
}

impl XdpContext {
    /// Creates a new XdpContext and attaches the internal XDP program to the given intreface name. Optionally enabling fragmentation.
    ///
    /// Note: fragmentation support will silently be ignored if the driver of the given interface does not support it.
    pub fn new(if_name: &str, attach_mode: AttachMode, enable_fragmentation: bool) -> Result<Self> {
        let program = XdpProgram::new(XDP_PROG_DATA, if_name, attach_mode, enable_fragmentation)?;

        XdpContext::with_compiled_program(program)
    }

    /// Creates a new XdpContext and attaches the given user supplied pre-compiled XDP program to the given intreface name. Optionally enabling fragmentation.
    ///
    /// Note: fragmentation support will silently be ignored if the driver of the given interface does not support it.
    pub fn with_program(
        program_data: &[u8],
        if_name: &str,
        attach_mode: AttachMode,
        enable_fragmentation: bool,
    ) -> Result<Self> {
        let program = XdpProgram::new(program_data, if_name, attach_mode, enable_fragmentation)?;

        XdpContext::with_compiled_program(program)
    }

    fn with_compiled_program(program: XdpProgram) -> Result<Self> {
        let data_map = program.find_map(".bss")?;
        let xsks_map = program.find_map("xsks_map")?;

        Ok(Self {
            data_map,
            xsks_map,
            num_sockets: 0,
            program,
        })
    }

    /// Returns the attach mode of the XDP program.
    pub fn attach_mode(&self) -> AttachMode {
        self.program.attach_mode()
    }

    /// Returns the information about the XDP program and its associated features.
    pub fn info(&self) -> &XdpInfo {
        self.program.info()
    }

    /// Registers a new socket with the XDP program, this will update the xsks_map and the num_sockets counter in the XDP program's .bss map.
    pub fn register_socket(&mut self, fd: i32) -> Result<()> {
        let loc = self.num_sockets;
        self.num_sockets += 1;

        // Update our xsks_map with the socket's file descriptor.
        unsafe { self.xsks_map.update_elem(&loc, &fd)? };

        const KEY: u32 = 0;
        // Update our num_sockets counter in the XDP program's .bss map.
        unsafe { self.data_map.update_elem(&KEY, &self.num_sockets)? };

        Ok(())
    }

    /// Returns the current socket count registered with this context.
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

        let ctx = XdpContext::new(veth.outer_name(), AttachMode::default(), true);
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
        let result = XdpContext::new("nonexistent_iface_xyz123", AttachMode::default(), true);
        assert!(result.is_err(), "expected error for non-existent interface");
    }

    /// Tests that multiple contexts can be created on different veth pairs.
    #[test]
    fn test_multiple_contexts_different_interfaces() {
        let veth1 = TestVethPair::new().expect("failed to create first veth pair");
        let veth2 = TestVethPair::new().expect("failed to create second veth pair");

        let ctx1 =
            XdpContext::new(veth1.outer_name(), AttachMode::default(), true).expect("context 1");
        let ctx2 =
            XdpContext::new(veth2.outer_name(), AttachMode::default(), true).expect("context 2");

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

        let ctx_outer =
            XdpContext::new(veth.outer_name(), AttachMode::default(), true).expect("outer context");
        let ctx_inner =
            XdpContext::new(veth.inner_name(), AttachMode::default(), true).expect("inner context");

        // Both should be valid with separate state.
        assert_eq!(ctx_outer.num_sockets(), 0);
        assert_eq!(ctx_inner.num_sockets(), 0);

        // Their MTUs should match since they're a pair.
        assert_eq!(ctx_outer.info().mtu, ctx_inner.info().mtu);
    }
}
