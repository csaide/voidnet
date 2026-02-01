use crate::xdp::{
    context::XdpContext,
    error::{NonBlocking, Result},
    frame::{Frame, FrameBuffer},
    socket::{CopyMode, Socket, SocketBuilder},
    umem::{Umem, UmemBuilder},
};

pub struct RawTransceiverBuilder<'if_name> {
    umem_builder: UmemBuilder,
    socket_builder: SocketBuilder<'if_name>,
}

impl<'if_name> RawTransceiverBuilder<'if_name> {
    pub fn new(if_name: &'if_name str, queue: u32) -> Self {
        Self {
            umem_builder: UmemBuilder::new(),
            socket_builder: SocketBuilder::new(if_name, queue),
        }
    }

    /// Sets the size of the completion ring, the maximum number of frames that can be outstanding in the completion ring.
    ///
    /// Note this value must be a power of two.
    pub fn completion_ring_size(mut self, completion_ring_size: u32) -> Self {
        self.umem_builder = self.umem_builder.completion_ring_size(completion_ring_size);
        self
    }

    /// Sets the size of the fill ring, the maximum number of frames that can be outstanding in the fill ring.
    ///
    /// Note this value must be a power of two.
    pub fn fill_ring_size(mut self, fill_ring_size: u32) -> Self {
        self.umem_builder = self.umem_builder.fill_ring_size(fill_ring_size);
        self
    }

    /// Sets the size of the frame, the size of each frame in the UMEM.
    ///
    /// Note this value must be a power of two.
    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.umem_builder = self.umem_builder.frame_size(frame_size);
        self
    }

    /// Sets the total number of frames in the UMEM.
    ///
    /// Note this value is optional, if not set it will be calculated as the sum of the completion and fill ring sizes.
    pub fn num_frames(mut self, num_frames: usize) -> Self {
        self.umem_builder = self.umem_builder.num_frames(num_frames);
        self
    }

    /// Sets whether to use huge tables for the UMEM.
    pub fn huge_tables(mut self, huge_tables: bool) -> Self {
        self.umem_builder = self.umem_builder.huge_tables(huge_tables);
        self
    }

    /// Sets whether to use unaligned chunks for the UMEM.
    pub fn unaligned(mut self, unaligned: bool) -> Self {
        self.umem_builder = self.umem_builder.unaligned(unaligned);
        self
    }

    /// Sets the size of the RX ring, the maximum number of frames that can be outstanding RX at a time in the kernel.
    ///
    /// Note: This value can be any power of two that fits in a u32, however note that the device driver has a limited number of RX descriptors available. That descriptor limit is effectively
    /// the upper bound of this value, any value greater will work as intended but you will not get any more throughput.
    pub fn rx_ring_size(mut self, rx_ring_size: u32) -> Self {
        self.socket_builder = self.socket_builder.rx_ring_size(rx_ring_size);
        self
    }

    /// Sets the size of the TX ring, the maximum number of frames that can be outstanding TX at a time in the kernel.
    ///
    /// Note: This value can be any power of two that fits in a u32, however note that the device driver has a limited number of TX descriptors available. That limit is effectively
    /// the upper bound of this value, any value greater will work as intended but you will not get any more throughput.
    pub fn tx_ring_size(mut self, tx_ring_size: u32) -> Self {
        self.socket_builder = self.socket_builder.tx_ring_size(tx_ring_size);
        self
    }

    /// Sets whether to use busy polling for the socket.
    pub fn busy_poll(mut self, busy_poll: bool) -> Self {
        self.umem_builder = self.umem_builder.busy_poll(busy_poll);
        self.socket_builder = self.socket_builder.busy_poll(busy_poll);
        self
    }

    /// Sets the busy poll batch size, this is the maximum number of frames to wait for while busy polling.
    pub fn busy_poll_batch_size(mut self, busy_poll_batch_size: usize) -> Self {
        self.socket_builder = self
            .socket_builder
            .busy_poll_batch_size(busy_poll_batch_size);
        self
    }

    /// Sets the busy poll timeout in microseconds, this is the maximum time to wait for a frame while busy polling.
    pub fn busy_poll_timeout_us(mut self, busy_poll_timeout_us: i32) -> Self {
        self.socket_builder = self
            .socket_builder
            .busy_poll_timeout_us(busy_poll_timeout_us);
        self
    }

    /// Sets the copy mode, this is the mode to use for copying packets to/from the socket.
    pub fn copy_mode(mut self, copy_mode: CopyMode) -> Self {
        self.socket_builder = self.socket_builder.copy_mode(copy_mode);
        self
    }

    /// Sets whether to enable fragmentation, this is the mode to use for copying packets to/from the socket.
    pub fn enable_fragmentation(mut self, enable_fragmentation: bool) -> Self {
        self.socket_builder = self
            .socket_builder
            .enable_fragmentation(enable_fragmentation);
        self
    }

    pub fn build<'umem, T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(
        self,
        ctx: &mut XdpContext,
    ) -> Result<RawTransceiver<'umem, T>> {
        let umem = self.umem_builder.build()?;
        let socket = self.socket_builder.build(ctx, umem.owner().clone())?;
        Ok(RawTransceiver::new(umem, socket))
    }
}

pub struct RawTransceiver<'umem, T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>> {
    umem: Umem<'umem>,
    socket: Socket<'umem>,
    buffer: T,
}

impl<'umem, T: FrameBuffer<'umem> + FromIterator<Frame<'umem>>> RawTransceiver<'umem, T> {
    pub fn builder(if_name: &str, queue: u32) -> RawTransceiverBuilder<'_> {
        RawTransceiverBuilder::new(if_name, queue)
    }

    fn new(umem: Umem<'umem>, socket: Socket<'umem>) -> Self {
        let buffer = umem.init_buffer::<T>().unwrap();
        Self {
            umem,
            socket,
            buffer,
        }
    }

    pub fn echo<F>(&mut self, f: F) -> NonBlocking<()>
    where
        F: FnOnce(T::IterMut<'_>),
    {
        self.umem.maybe_wake_fill_queue(self.socket.fd()).unwrap();
        self.umem.process_fill_queue(&mut self.buffer);

        self.socket.recv(&mut self.buffer)?;

        f(self.buffer.iter_frames_mut());

        while let Err(_) = self.socket.send(&mut self.buffer) {
            self.socket.maybe_wake().unwrap();
        }

        while let Err(_) = self.umem.process_completion_queue(&mut self.buffer) {
            self.socket.maybe_wake().unwrap();
        }

        self.umem.maybe_wake_fill_queue(self.socket.fd()).unwrap();
        self.umem.process_fill_queue(&mut self.buffer);

        Ok(())
    }
}
