use crate::xdp::{
    program::{Map, XdpProgram},
    socket::Socket,
};

use crate::xdp::error::Result;

// We ship our little XDP router directly embedded in this library as raw ELF data.
static XDP_PROG_DATA: &'static [u8] = include_bytes!("../../../bpf/xdp_kern.o");

pub struct XdpContext {
    _program: XdpProgram,
    data_map: Map,
    xsks_map: Map,
    num_sockets: u32,
}

impl XdpContext {
    pub fn new(if_name: &str) -> Result<Self> {
        let mut program = XdpProgram::new(XDP_PROG_DATA)?;
        program.attach(if_name)?;

        let data_map = program.find_map(".bss")?;
        let xsks_map = program.find_map("xsks_map")?;

        Ok(Self {
            _program: program,
            data_map,
            xsks_map,
            num_sockets: 0,
        })
    }

    pub fn register_socket(&mut self, socket: &Socket) -> Result<()> {
        let loc = self.num_sockets;
        self.num_sockets += 1;

        let key = 0;
        // Update our num_sockets counter in the XDP program's .bss map.
        self.data_map.update_elem(&key, &self.num_sockets)?;

        // Update our xsks_map with the socket's file descriptor.
        self.xsks_map.update_elem(&loc, &socket.fd())
    }
}
