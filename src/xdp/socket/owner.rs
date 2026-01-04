use std::sync::Arc;

use libc::c_int;
use libxdp_sys::{xsk_socket, xsk_socket__delete};

use crate::xdp::umem::UmemOwner;

/// A frame based XDP socket exposing zero copy batched receive and send operations.
pub struct SocketOwner<'umem> {
    // We need the Umem to live longer than us, as all of our memory is directly owned by the Umem.
    pub(super) umem: Arc<UmemOwner<'umem>>,
    pub(super) socket: *mut xsk_socket,
    pub(super) fd: c_int,
}

// SAFETY: SocketOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Sync for SocketOwner<'umem> {}

// SAFETY: SocketOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Send for SocketOwner<'umem> {}

impl<'umem> Drop for SocketOwner<'umem> {
    fn drop(&mut self) {
        unsafe {
            // No null pointer check here because it is initialized to null and if the create fails,
            // it should still be null and xsk_socket__delete handles null.
            xsk_socket__delete(self.socket);
        }
    }
}
