use crate::xdp::{
    context::XdpContext,
    error::{NonBlocking, Result},
    frame::{Frame, FrameBuffer},
    socket::{Socket, SocketBuilder},
    umem::{Umem, UmemBuilder},
};

pub struct RawSenderBuilder<'if_name> {
    umem_builder: UmemBuilder,
    socket_builder: SocketBuilder<'if_name>,
    num_frames: usize,
}

impl<'if_name> RawSenderBuilder<'if_name> {
    pub fn new(if_name: &'if_name str, queue: u32) -> Self {
        Self {
            umem_builder: UmemBuilder::new(),
            socket_builder: SocketBuilder::new(if_name, queue),
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

    pub fn build<'umem, T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(
        self,
        ctx: &mut XdpContext,
    ) -> Result<(RawSender<'umem>, T)> {
        let umem = self
            .umem_builder
            .num_frames(self.num_frames)
            .completion_ring_size(self.num_frames as u32)
            .build()?;
        let socket = self
            .socket_builder
            .tx_ring_size(self.num_frames as u32)
            .build(ctx, umem.owner().clone())?;
        Ok(RawSender::new(umem, socket))
    }
}

pub struct RawSender<'umem> {
    umem: Umem<'umem>,
    socket: Socket<'umem>,
}

impl<'umem> RawSender<'umem> {
    pub fn builder(if_name: &str, queue: u32) -> RawSenderBuilder<'_> {
        RawSenderBuilder::new(if_name, queue)
    }

    fn new<T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(
        umem: Umem<'umem>,
        socket: Socket<'umem>,
    ) -> (Self, T) {
        let buffer = umem.init_buffer::<T>().unwrap();
        (Self { umem, socket }, buffer)
    }

    pub fn send<B: FrameBuffer<'umem>>(&mut self, mut batch: B) -> NonBlocking<u32> {
        let sent = match self.socket.send(&mut batch) {
            Ok(sent) => sent,
            e => {
                self.socket.maybe_wake().unwrap();
                return e;
            }
        };

        let mut processed = 0;
        while processed < sent {
            processed += match self.umem.process_completion_queue(&mut batch) {
                Ok(processed) => processed,
                _ => {
                    self.socket.maybe_wake().unwrap();
                    continue;
                }
            };
        }

        Ok(sent)
    }
}
