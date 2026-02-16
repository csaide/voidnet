use std::{
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    net::wire::ip::{IpAddress, Ipv4Address},
    xdp::{
        error::Result,
        frame::{BasicFrameBuffer, Frame, FrameBuffer},
    },
};

pub struct UdpSocket<'umem> {
    id: u32,
    local_addr: IpAddress,
    local_port: u16,
    rx_buffer: BasicFrameBuffer<'umem>,
    tx_buffer: BasicFrameBuffer<'umem>,
}

impl<'umem> UdpSocket<'umem> {
    pub fn new(id: u32, local_addr: IpAddress, local_port: u16) -> Self {
        Self {
            id,
            local_addr,
            local_port,
            rx_buffer: BasicFrameBuffer::new(1024),
            tx_buffer: BasicFrameBuffer::new(1024),
        }
    }
    pub fn sendto(&self, dst_addr: IpAddress, dst_port: u16, data: &[u8]) -> Result<()> {
        Ok(())
    }

    pub fn recvfrom(&mut self) -> UdpRecvFuture<'_, 'umem> {
        UdpRecvFuture::new(&mut self.rx_buffer)
    }
}

pub struct UdpSendFuture<'sock, 'umem> {
    tx_buffer: &'sock mut BasicFrameBuffer<'umem>,
    frame: Option<Frame<'umem>>,
}

impl<'sock, 'umem> UdpSendFuture<'sock, 'umem> {
    pub fn new(tx_buffer: &'sock mut BasicFrameBuffer<'umem>, frame: Frame<'umem>) -> Self {
        Self {
            tx_buffer,
            frame: Some(frame),
        }
    }
}

impl<'sock, 'umem> Future for UdpSendFuture<'sock, 'umem> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.tx_buffer.free_space() == 0 {
            return Poll::Pending;
        }

        let this = unsafe { self.get_unchecked_mut() };
        match this.frame.take() {
            Some(frame) => {
                this.tx_buffer.push(frame);
                Poll::Ready(Ok(()))
            }
            None => unreachable!(), // It is an error to call this function after Poll::Ready() is returned.
        }
    }
}

pub struct UdpRecvFuture<'sock, 'umem> {
    rx_buffer: &'sock mut BasicFrameBuffer<'umem>,
}

impl<'sock, 'umem> UdpRecvFuture<'sock, 'umem> {
    pub fn new(rx_buffer: &'sock mut BasicFrameBuffer<'umem>) -> Self {
        Self { rx_buffer }
    }
}

impl<'sock, 'umem> Future for UdpRecvFuture<'sock, 'umem> {
    type Output = Result<Frame<'umem>>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match unsafe { self.get_unchecked_mut() }.rx_buffer.pop() {
            Some(frame) => Poll::Ready(Ok(frame)),
            None => Poll::Pending,
        }
    }
}
