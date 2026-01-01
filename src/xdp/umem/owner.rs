use libxdp_sys::{xsk_umem, xsk_umem__delete};
use memmap2::MmapMut;

use crate::xdp::frame::Frame;

pub struct UmemOwner {
    pub(super) umem: *mut xsk_umem,
    pub(super) mmap: MmapMut,
    pub(super) frame_size: usize,
}

unsafe impl Send for UmemOwner {}
unsafe impl Sync for UmemOwner {}

impl UmemOwner {
    pub fn to_frame(&self, addr: u64, len: usize, is_fragment: bool) -> Frame {
        unsafe {
            Frame::new(
                addr,
                self.mmap.as_ptr().offset(addr as isize) as *mut u8,
                len,
                self.frame_size,
                is_fragment,
            )
        }
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
