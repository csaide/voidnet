use std::{os::fd::RawFd, sync::Arc};

use tokio::io::unix::AsyncFd;

use crate::xdp::{
    error::Result,
    frame::FrameBuffer,
    socket::{SocketOwner, SocketRx, SocketTx},
};

use super::{TokioRecvFuture, TokioSendFuture, TokioSocketRx, TokioSocketTx};

pub struct TokioSocket<'umem> {
    owner: Arc<SocketOwner<'umem>>,
    rx: TokioSocketRx<'umem>,
    tx: TokioSocketTx<'umem>,
}

impl<'umem> TokioSocket<'umem> {
    pub fn new(
        owner: Arc<SocketOwner<'umem>>,
        rx: SocketRx<'umem>,
        tx: SocketTx<'umem>,
        async_fd: Arc<AsyncFd<RawFd>>,
    ) -> Self {
        Self {
            owner,
            rx: TokioSocketRx::new(rx, async_fd.clone()),
            tx: TokioSocketTx::new(tx, async_fd),
        }
    }

    /// Splits the socket into its owner, rx, and tx components.
    #[inline(always)]
    pub fn split(
        self,
    ) -> (
        Arc<SocketOwner<'umem>>,
        TokioSocketRx<'umem>,
        TokioSocketTx<'umem>,
    ) {
        (self.owner, self.rx, self.tx)
    }

    /// Returns the file descriptor of the socket.
    #[inline(always)]
    pub fn fd(&self) -> RawFd {
        self.owner.fd()
    }

    /// Possibly wakes the tx queue, so the kernel continues to process outgoing packets.
    #[inline(always)]
    pub fn maybe_wake(&self) -> Result<()> {
        self.tx.maybe_wake()
    }

    /// Receives a batch of frames from the socket.
    #[inline(always)]
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> TokioRecvFuture<'_, 'umem, B> {
        self.rx.recv(batch)
    }

    /// Sends a batch of frames to the socket.
    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, frames: B) -> TokioSendFuture<'_, 'umem, B> {
        self.tx.send(frames)
    }
}
