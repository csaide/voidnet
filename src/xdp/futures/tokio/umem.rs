use std::{
    os::{fd::RawFd, raw::c_int},
    sync::Arc,
};

use tokio::io::unix::AsyncFd;

use crate::xdp::{
    frame::{Frame, FrameBuffer},
    futures::{TokioCompFuture, TokioCompletionQueue, TokioFillFuture, TokioFillQueue},
    umem::{CompletionQueue, FillQueue, UmemOwner},
};

/// A UMEM designed to work on the [Tokio] runtime.
///
/// [Tokio]: tokio
pub struct TokioUmem<'umem> {
    owner: Arc<UmemOwner<'umem>>,
    fill_queue: TokioFillQueue<'umem>,
    completion_queue: TokioCompletionQueue<'umem>,
}

impl<'umem> TokioUmem<'umem> {
    pub(crate) fn new(
        owner: Arc<UmemOwner<'umem>>,
        fill_queue: FillQueue<'umem>,
        completion_queue: CompletionQueue<'umem>,
        async_fd: Arc<AsyncFd<RawFd>>,
    ) -> Self {
        Self {
            owner,
            fill_queue: TokioFillQueue::new(fill_queue, async_fd.clone()),
            completion_queue: TokioCompletionQueue::new(completion_queue, async_fd),
        }
    }

    /// Splits the umem into its owner, fill queue, and completion queue components.
    #[inline(always)]
    pub fn split(
        self,
    ) -> (
        Arc<UmemOwner<'umem>>,
        TokioFillQueue<'umem>,
        TokioCompletionQueue<'umem>,
    ) {
        (self.owner, self.fill_queue, self.completion_queue)
    }

    /// Returns the owner of the umem.
    #[inline(always)]
    pub fn owner(&self) -> &Arc<UmemOwner<'umem>> {
        &self.owner
    }

    /// Initialize the frame buffer with the frames from the UMEM, its then up to the caller what to do with these frames, you can push them into the fill queue, use them
    /// for writing packets, or some combination of the two. This can only be called once on the [UmemOwner] instance, and will return None on every subsequent call.
    pub fn init_buffer<B: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(&self) -> Option<B> {
        self.owner.init_buffer()
    }

    /// Processes the fill queue, allocating new frames from the frame stack and submitting them to the fill ring up to the size of the fill ring.
    #[inline(always)]
    pub fn process_fill_queue<'fd, B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
        fds: &'fd [c_int],
    ) -> TokioFillFuture<'_, 'umem, 'fd, B> {
        self.fill_queue.process_queue(batch, fds)
    }

    /// Processes the completion queue, allocating new frames from the frame stack and submitting them to the completion ring up to the size of the completion ring.
    #[inline(always)]
    pub fn process_completion_queue<'que, B: FrameBuffer<'umem>>(
        &'que mut self,
        batch: B,
    ) -> TokioCompFuture<'que, 'umem, B> {
        self.completion_queue.process_queue(batch)
    }
}
