use std::sync::Arc;

use libc::c_int;
use libxdp_sys::{xsk_socket, xsk_socket__delete, xsk_socket__fd};

use crate::xdp::umem::UmemOwner;

/// A frame based XDP socket exposing zero copy batched receive and send operations.
pub struct SocketOwner<'umem> {
    // We need the Umem to live longer than us, as all of our memory is directly owned by the Umem.
    umem: Arc<UmemOwner<'umem>>,
    socket: *mut xsk_socket,
    fd: c_int,
}

// SAFETY: SocketOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Sync for SocketOwner<'umem> {}

// SAFETY: SocketOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Send for SocketOwner<'umem> {}

impl<'umem> SocketOwner<'umem> {
    pub(super) fn new(umem: Arc<UmemOwner<'umem>>, socket: *mut xsk_socket) -> Self {
        Self {
            umem,
            socket,
            fd: unsafe { xsk_socket__fd(socket) },
        }
    }

    pub(crate) fn fd(&self) -> c_int {
        self.fd
    }

    pub(crate) fn umem(&self) -> &Arc<UmemOwner<'umem>> {
        &self.umem
    }
}

impl<'umem> Drop for SocketOwner<'umem> {
    fn drop(&mut self) {
        unsafe {
            // No null pointer check here because it is initialized to null and if the create fails,
            // it should still be null and xsk_socket__delete handles null.
            xsk_socket__delete(self.socket);
        }
    }
}
