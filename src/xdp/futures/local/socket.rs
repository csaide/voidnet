use std::{os::fd::RawFd, sync::Arc};

use crate::xdp::{
    error::Result,
    frame::FrameBuffer,
    socket::{SocketOwner, SocketRx, SocketTx},
};

use super::{LocalRecvFuture, LocalSendFuture, LocalSocketRx, LocalSocketTx};

pub struct LocalSocket<'umem> {
    owner: Arc<SocketOwner<'umem>>,
    rx: LocalSocketRx<'umem>,
    tx: LocalSocketTx<'umem>,
}

impl<'umem> LocalSocket<'umem> {
    pub fn new(
        owner: Arc<SocketOwner<'umem>>,
        rx: SocketRx<'umem>,
        tx: SocketTx<'umem>,
    ) -> Result<Self> {
        Ok(Self {
            owner,
            rx: LocalSocketRx::new(rx)?,
            tx: LocalSocketTx::new(tx)?,
        })
    }

    /// Splits the socket into its owner, rx, and tx components.
    #[inline(always)]
    pub fn split(
        self,
    ) -> (
        Arc<SocketOwner<'umem>>,
        LocalSocketRx<'umem>,
        LocalSocketTx<'umem>,
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
    pub fn recv<B: FrameBuffer<'umem>>(&mut self, batch: B) -> LocalRecvFuture<'_, 'umem, B> {
        self.rx.recv(batch)
    }

    /// Sends a batch of frames to the socket.
    #[inline(always)]
    pub fn send<B: FrameBuffer<'umem>>(&mut self, frames: B) -> LocalSendFuture<'_, 'umem, B> {
        self.tx.send(frames)
    }
}
