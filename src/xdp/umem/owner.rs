use std::sync::Arc;

use libxdp_sys::{xsk_umem, xsk_umem__delete};
use memmap2::MmapMut;

use crate::xdp::frame::Frame;

/// The owner of a UMEM, this is used to create frames and is responsible for cleaning up the UMEM once all is said and done.
pub struct UmemOwner {
    pub(super) umem: *mut xsk_umem,
    pub(super) mmap: Arc<MmapMut>,
    pub(super) frame_size: usize,
}

// SAFETY: UmemOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl Send for UmemOwner {}

// SAFETY: UmemOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl Sync for UmemOwner {}

impl UmemOwner {
    /// Creates a new frame from the given address and length.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `len`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `len`, which is fully initialized.
    pub unsafe fn to_frame(&self, addr: u64, len: usize, is_fragment: bool) -> Frame {
        unsafe { Frame::new(addr, len, self.frame_size, is_fragment, self.mmap.clone()) }
    }
}

impl Drop for UmemOwner {
    fn drop(&mut self) {
        // SAFETY: xsk_umem__delete is safe to call even if the umem is not initialized.
        unsafe {
            xsk_umem__delete(self.umem);
        }
    }
}
