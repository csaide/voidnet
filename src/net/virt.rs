use crate::xdp::{
    error::NonBlocking,
    frame::{FrameBuffer, Packet},
    socket::Socket,
};

pub struct PacketProcessor {
    _current: Packet,
    socket: Socket,
}

impl PacketProcessor {
    pub fn new(socket: Socket) -> Self {
        Self {
            _current: Packet::new(32, 2),
            socket,
        }
    }

    pub fn recv<B: FrameBuffer>(&mut self, batch: B) -> NonBlocking<u32> {
        self.socket.recv(batch)
    }
}
