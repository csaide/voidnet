use crate::xdp::{
    context::XdpContext,
    error::{NonBlocking, Result},
    frame::{Frame, FrameBuffer},
    socket::{CopyMode, Socket, SocketBuilder},
    umem::{Umem, UmemBuilder},
};

pub struct RawReceiverBuilder<'if_name> {
    umem_builder: UmemBuilder,
    socket_builder: SocketBuilder<'if_name>,
    num_frames: usize,
}

impl<'if_name> RawReceiverBuilder<'if_name> {
    pub(crate) fn new(if_name: &'if_name str, queue: u32) -> Self {
        let umem_builder = UmemBuilder::new();
        let socket_builder = SocketBuilder::new(if_name, queue);
        Self {
            umem_builder,
            socket_builder,
            num_frames: 4096,
        }
    }

    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.umem_builder = self.umem_builder.frame_size(frame_size);
        self
    }

    pub fn num_frames(mut self, num_frames: usize) -> Self {
        self.num_frames = num_frames;
        self
    }

    pub fn huge_tables(mut self, huge_tables: bool) -> Self {
        self.umem_builder = self.umem_builder.huge_tables(huge_tables);
        self
    }

    pub fn unaligned(mut self, unaligned: bool) -> Self {
        self.umem_builder = self.umem_builder.unaligned(unaligned);
        self
    }

    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.umem_builder = self.umem_builder.busy_poll(busy_poll);
        self.socket_builder = self.socket_builder.busy_poll(busy_poll);
        self
    }

    pub fn busy_poll_batch_size(mut self, busy_poll_batch_size: usize) -> Self {
        self.socket_builder = self
            .socket_builder
            .busy_poll_batch_size(busy_poll_batch_size);
        self
    }

    pub fn busy_poll_timeout_us(mut self, busy_poll_timeout_us: i32) -> Self {
        self.socket_builder = self
            .socket_builder
            .busy_poll_timeout_us(busy_poll_timeout_us);
        self
    }

    pub fn copy_mode(mut self, copy_mode: CopyMode) -> Self {
        self.socket_builder = self.socket_builder.copy_mode(copy_mode);
        self
    }

    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.socket_builder = self
            .socket_builder
            .enable_fragmentation(enable_fragmentation);
        self
    }

    pub fn build<'umem, T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(
        self,
        ctx: &mut XdpContext,
    ) -> Result<RawReceiver<'umem, T>> {
        let umem = self
            .umem_builder
            .num_frames(self.num_frames)
            .fill_ring_size(self.num_frames as u32)
            .build()?;
        let socket = self
            .socket_builder
            .rx_ring_size(self.num_frames as u32)
            .build(ctx, umem.owner().clone())?;
        Ok(RawReceiver::new(umem, socket))
    }
}

pub struct RawReceiver<'umem, T: FrameBuffer<'umem>> {
    umem: Umem<'umem>,
    buffer: T,
    socket: Socket<'umem>,
}

impl<'umem, T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>> RawReceiver<'umem, T> {
    pub fn builder(if_name: &str, queue: u32) -> RawReceiverBuilder<'_> {
        RawReceiverBuilder::new(if_name, queue)
    }

    fn new(umem: Umem<'umem>, socket: Socket<'umem>) -> Self {
        let buffer = umem.init_buffer::<T>().unwrap();
        Self {
            umem,
            buffer,
            socket,
        }
    }

    pub fn recv(&mut self) -> NonBlocking<T::Iter<'_>> {
        self.umem.maybe_wake_fill_queue(self.socket.fd()).unwrap();
        self.umem.process_fill_queue(&mut self.buffer);

        self.socket.recv(&mut self.buffer)?;

        Ok(self.buffer.iter_frames())
    }
}
