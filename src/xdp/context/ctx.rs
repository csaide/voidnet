use crate::xdp::{
    error::Result,
    program::{AttachMode, Map, XdpInfo, XdpProgram},
    socket::Socket,
};

// We ship our little XDP router directly embedded in this library as raw ELF data.
static XDP_PROG_DATA: &'static [u8] = include_bytes!("../../../bpf/xdp_kern.o");

pub struct XdpContext {
    data_map: Map,
    xsks_map: Map,
    num_sockets: u32,
    program: XdpProgram,
}

impl XdpContext {
    pub fn new(if_name: &str, attach_mode: AttachMode, enable_fragmentation: bool) -> Result<Self> {
        let program = XdpProgram::new(XDP_PROG_DATA, if_name, attach_mode, enable_fragmentation)?;

        let data_map = program.find_map(".bss")?;
        let xsks_map = program.find_map("xsks_map")?;

        Ok(Self {
            data_map,
            xsks_map,
            num_sockets: 0,
            program,
        })
    }

    pub fn attach_mode(&self) -> AttachMode {
        self.program.attach_mode()
    }

    pub fn info(&self) -> &XdpInfo {
        self.program.info()
    }

    pub fn register_socket(&mut self, socket: &Socket) -> Result<()> {
        let loc = self.num_sockets;
        self.num_sockets += 1;

        const KEY: u32 = 0;
        // Update our num_sockets counter in the XDP program's .bss map.
        self.data_map.update_elem(&KEY, &self.num_sockets)?;

        // Update our xsks_map with the socket's file descriptor.
        self.xsks_map.update_elem(&loc, &socket.fd())
    }
}
