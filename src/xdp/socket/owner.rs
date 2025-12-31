use std::sync::Arc;

use libc::c_int;
use libxdp_sys::{xsk_socket, xsk_socket__delete};

use crate::xdp::umem::Umem;

/// A frame based XDP socket exposing zero copy batched receive and send operations.
pub struct SocketOwner {
    // We need the Umem to live longer than us, as all of our memory is directly owned by the Umem.
    pub(super) _umem: Arc<Umem>,
    pub(super) socket: *mut xsk_socket,
    pub(super) fd: c_int,
}

impl SocketOwner {
    pub fn fd(&self) -> c_int {
        self.fd
    }
}

unsafe impl Sync for SocketOwner {}
unsafe impl Send for SocketOwner {}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        unsafe {
            // No null pointer check here because it is initialized to null and if the create fails,
            // it should still be null and xsk_socket__delete handles null.
            xsk_socket__delete(self.socket);
        }
    }
}
