use std::{marker::PhantomData, mem::transmute, sync::Arc};

use libc::XDP_PKT_CONTD;
use libxdp_sys::XSK_UNALIGNED_BUF_ADDR_MASK;

use crate::{
    futures::RecvFuture,
    xdp::{
        error::{NonBlocking, WouldBlock},
        frame_v2::{Frame, FrameBuffer},
        ring::{Consumer, Init},
        umem::UmemOwner,
    },
};

use super::SocketOwner;

pub struct SocketRx {
    _socket: Arc<SocketOwner>,
    ring: Consumer<Init>,
    owner: Arc<UmemOwner>,
}

impl SocketRx {
    pub fn new(socket: Arc<SocketOwner>, ring: Consumer<Init>, owner: Arc<UmemOwner>) -> Self {
        Self {
            _socket: socket,
            ring,
            owner,
        }
    }

    #[inline(always)]
    pub fn recv<'umem, B: FrameBuffer<'umem>>(&mut self, mut batch: B) -> NonBlocking<u32> {
        // Take at least 1 frame up to the number of free slots in the batch.
        let (mut idx_rx, rcvd) = self.ring.peek(batch.free_space() as u32);
        if rcvd == 0 {
            return Err(WouldBlock);
        }

        for _ in 0..rcvd as usize {
            let desc = self.ring.rx_desc(idx_rx);
            // SAFETY: The address/length/options are valid because it is from the RX ring and kernel guarantees them.
            let frame = self.owner.to_frame(
                xsk_umem_extract_addr(desc.addr),
                desc.len as usize,
                desc.options & XDP_PKT_CONTD == XDP_PKT_CONTD,
            );

            let frame = unsafe { transmute::<Frame<'_>, Frame<'umem>>(frame) };
            batch.push(frame);
            idx_rx += 1;
        }

        self.ring.release(rcvd);
        Ok(rcvd)
    }

    #[inline(always)]
    pub fn recv_async<'umem, B: FrameBuffer<'umem>>(
        &mut self,
        batch: B,
    ) -> RecvFuture<'_, 'umem, B> {
        RecvFuture {
            socket: self,
            batch,
            _lifetime: PhantomData,
        }
    }
}

#[inline(always)]
pub fn xsk_umem_extract_addr(addr: u64) -> u64 {
    addr & XSK_UNALIGNED_BUF_ADDR_MASK
}
