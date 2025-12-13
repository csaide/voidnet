use std::ffi::CString;
use std::mem::ManuallyDrop;

use errno::errno;
use libc::c_int;
use libxdp_sys::{
    XDP_USE_NEED_WAKEUP, XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS,
    XSK_UMEM__DEFAULT_FRAME_SIZE, xsk_socket, xsk_socket__create, xsk_socket__delete,
    xsk_socket__fd, xsk_socket_config, xsk_socket_config__bindgen_ty_1,
};

use crate::xdp::ring::{Consumer, Producer, Tx};
use crate::xdp::umem::{Frame, Umem};

use super::{Error, Result};

/// Builder for creating a new socket.
pub struct SocketBuilder {
    if_name: CString,
    queue: u32,
    rx_ring_size: u32,
    tx_ring_size: u32,
    completion_ring_size: u32,
    fill_ring_size: u32,
    frame_size: usize,
}

impl SocketBuilder {
    /// Creates a new socket builder, using the supllied interface name and queue number.
    ///
    /// The defaults included are sane values for most use cases.
    pub fn new(if_name: &str, queue: u32) -> Self {
        let if_name =
            CString::new(if_name).expect("Some how a rust string was null terminated....");
        Self {
            if_name,
            queue,
            rx_ring_size: XSK_RING_CONS__DEFAULT_NUM_DESCS,
            tx_ring_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
            completion_ring_size: XSK_RING_CONS__DEFAULT_NUM_DESCS,
            fill_ring_size: XSK_RING_PROD__DEFAULT_NUM_DESCS,
            frame_size: XSK_UMEM__DEFAULT_FRAME_SIZE as usize,
        }
    }

    /// Sets the size of the RX ring.
    pub fn rx_ring_size(mut self, rx_ring_size: u32) -> Self {
        self.rx_ring_size = rx_ring_size;
        self
    }

    /// Sets the size of the TX ring.
    pub fn tx_ring_size(mut self, tx_ring_size: u32) -> Self {
        self.tx_ring_size = tx_ring_size;
        self
    }

    /// Sets the size of the completion ring.
    pub fn completion_ring_size(mut self, completion_ring_size: u32) -> Self {
        self.completion_ring_size = completion_ring_size;
        self
    }

    /// Sets the size of the fill ring.
    pub fn fill_ring_size(mut self, fill_ring_size: u32) -> Self {
        self.fill_ring_size = fill_ring_size;
        self
    }

    /// Sets the size of the frame.
    pub fn frame_size(mut self, frame_size: usize) -> Self {
        self.frame_size = frame_size;
        self
    }

    /// Builds the socket.
    pub fn build(self) -> Result<Socket> {
        // First create the UMEM object, this will allocate the frames and the completion/fill rings.
        let umem = Umem::builder()
            .completion_ring_size(self.completion_ring_size)
            .fill_ring_size(self.fill_ring_size)
            .frame_size(self.frame_size)
            .num_frames((self.completion_ring_size + self.fill_ring_size) as usize)
            .build()?;

        // Then create the socket, this will allocate the RX/TX rings and bind the socket + rings to the UMEM object.
        let socket = Socket::new(
            self.if_name.as_c_str().to_str().unwrap(),
            self.queue,
            umem,
            self.rx_ring_size,
            self.tx_ring_size,
        )?;
        Ok(socket)
    }
}

/// A frame based XDP socket exposing zero copy batched receive and send operations.
pub struct Socket {
    umem: Umem,
    socket: Box<xsk_socket>,
    fd: c_int,
    rx: Consumer,
    tx: Producer<Tx>,
}

impl Socket {
    /// Returns a builder for creating a new socket.
    pub fn builder(if_name: &str, queue: u32) -> SocketBuilder {
        SocketBuilder::new(if_name, queue)
    }

    fn new(
        if_name: &str,
        queue: u32,
        mut umem: Umem,
        rx_ring_size: u32,
        tx_ring_size: u32,
    ) -> Result<Self> {
        let cfg = xsk_socket_config {
            rx_size: rx_ring_size,
            tx_size: tx_ring_size,
            xdp_flags: 0,
            bind_flags: XDP_USE_NEED_WAKEUP as u16,
            __bindgen_anon_1: xsk_socket_config__bindgen_ty_1 { libxdp_flags: 0 },
        };

        let mut rx = Consumer::new(rx_ring_size);
        let mut tx = Producer::new_tx(tx_ring_size);

        // C function has double indirection
        let mut xsk: *mut xsk_socket = std::ptr::null_mut();
        let xsk_ptr: *mut *mut xsk_socket = &mut xsk;

        let if_name_c = CString::new(if_name).unwrap();

        let ret: std::os::raw::c_int;
        unsafe {
            ret = xsk_socket__create(
                xsk_ptr,
                if_name_c.as_ptr(),
                queue as u32,
                umem.umem(),
                rx.as_mut(),
                tx.as_mut(),
                &cfg,
            );
        }

        if ret != 0 {
            return Err(Error::Create(errno()));
        }

        Ok(Self {
            umem,
            socket: unsafe { Box::from_raw(*xsk_ptr) },
            fd: unsafe { xsk_socket__fd(*xsk_ptr) },
            rx,
            tx,
        })
    }

    /// Receives a batch of frames from the socket.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is received.
    ///
    /// If no frames are availabel to read this returns an error of type [Error::WouldBlock].
    pub fn recv(&mut self, batch_size: u32) -> Result<Vec<Frame>> {
        let (mut idx_rx, rcvd) = match self.rx.peek(batch_size) {
            Some((idx, rcvd)) => (idx, rcvd),
            None => {
                self.umem.maybe_wake(self.fd)?;
                self.umem.process_fill_queue();
                return Err(Error::WouldBlock);
            }
        };

        let mut batch = Vec::with_capacity(rcvd as usize);
        for _ in 0..rcvd {
            let desc = self.rx.rx_desc(idx_rx);
            batch.push(self.umem.get_frame(desc.addr, desc.len as usize));
            idx_rx += 1;
        }

        self.rx.release(rcvd);

        Ok(batch)
    }

    /// Prepares a batch of frames for sending.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is prepared.
    ///
    /// If no frames are availabel to prepare this returns an error of type [Error::WouldBlock].
    pub fn prepare_frames(&mut self, num_frames: usize) -> Result<Vec<Frame>> {
        let mut frames = Vec::with_capacity(num_frames);
        for _ in 0..num_frames {
            if let Some(frame) = self.umem.pop_frame() {
                frames.push(frame);
            } else {
                self.tx.maybe_wake(self.fd)?;
                self.umem.process_comp_queue();
                return Err(Error::WouldBlock);
            }
        }
        Ok(frames)
    }

    /// Sends a batch of frames to the socket.
    ///
    /// Note that it is not guaranteed that the resulting Vec of frames will match the batch size supplied.
    /// It is considered a batch maximum and this function will return as soon as at least one frame is sent.
    ///
    /// The caller should call this function until their batch of frames is empty.
    ///
    /// If no frames are availabel to send this returns an error of type [Error::WouldBlock].
    pub fn send(&mut self, frames: &mut Vec<Frame>) -> Result<()> {
        let (mut idx_tx, ready) = match self.tx.reserve(frames.len() as u32) {
            Some((idx_tx, ready)) => (idx_tx, ready),
            None => {
                self.tx.maybe_wake(self.fd)?;
                self.umem.process_comp_queue();
                return Err(Error::WouldBlock);
            }
        };

        for _ in 0..ready {
            let frame = frames.pop().map(ManuallyDrop::new).unwrap();
            let desc = self.tx.tx_desc(idx_tx);
            unsafe {
                (*desc).addr = frame.addr();
                (*desc).len = frame.len() as u32;
                (*desc).options = 0;
            }
            idx_tx += 1;
        }

        self.tx.submit(ready);
        Ok(())
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            // No null pointer check here because it is initialized to null and if the create fails,
            // it should still be null and xsk_socket__delete handles null.
            xsk_socket__delete(self.socket.as_mut());
        }
    }
}
