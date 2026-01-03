use crate::xdp::{
    error::Result,
    program::{AttachMode, Map, XdpInfo, XdpProgram},
    socket::Socket,
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
    pub fn register_socket(&mut self, socket: &Socket) -> Result<()> {
        let loc = self.num_sockets;
        self.num_sockets += 1;

        // Update our xsks_map with the socket's file descriptor.
        unsafe { self.xsks_map.update_elem(&loc, &socket.fd())? };

        const KEY: u32 = 0;
        // Update our num_sockets counter in the XDP program's .bss map.
        unsafe { self.data_map.update_elem(&KEY, &self.num_sockets)? };

        Ok(())
    }
}
