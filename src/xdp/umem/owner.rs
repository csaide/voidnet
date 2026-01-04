use std::{
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use libxdp_sys::{xsk_umem, xsk_umem__delete};
use memmap2::MmapMut;

use crate::xdp::frame::{Frame, FrameBuffer};

/// The owner of a UMEM, this is used to create frames and is responsible for cleaning up the UMEM once all is said and done.
pub struct UmemOwner<'umem> {
    pub(super) umem: *mut xsk_umem,
    pub(super) mmap: Arc<MmapMut>,
    pub(super) frame_size: usize,
    pub(super) num_frames: usize,
    pub(super) init: AtomicBool,
    // So why is this here? We need to have _some_ frame lifetime but we going to end up wrapped as an Arc<UmemOwner> and guess what that loses...
    pub(super) _lifetime: PhantomData<&'umem ()>,
}

// SAFETY: UmemOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Send for UmemOwner<'umem> {}

// SAFETY: UmemOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Sync for UmemOwner<'umem> {}

impl<'umem> UmemOwner<'umem> {
    /// Creates a new frame from the given address and length.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `len`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `len`, which is fully initialized.
    pub fn to_frame(&self, addr: u64, len: usize, is_fragment: bool) -> Frame<'umem> {
        debug_assert!(len <= self.frame_size, "len is greater than the frame size");
        debug_assert!(
            addr + len as u64 <= self.mmap.len() as u64,
            "addr + len is greater than the mmap length"
        );

        unsafe {
            Frame::new(
                addr,
                std::slice::from_raw_parts_mut(
                    self.mmap.as_ptr().offset(addr as isize) as *mut u8,
                    self.frame_size,
                ),
                len,
                self.frame_size,
                is_fragment,
            )
        }
    }

    pub fn as_ptr(&self) -> *mut xsk_umem {
        self.umem
    }

    pub fn init_buffer<B: FrameBuffer<'umem> + FromIterator<Frame<'umem>>>(&self) -> Option<B> {
        if self.init.swap(true, Ordering::AcqRel) {
            return None;
        }

        Some(
            (0..self.num_frames)
                .map(|i| self.to_frame(i as u64 * self.frame_size as u64, 0, false))
                .collect(),
        )
    }
}

impl<'umem> Drop for UmemOwner<'umem> {
    fn drop(&mut self) {
        // SAFETY: xsk_umem__delete is safe to call even if the umem is not initialized.
        unsafe {
            xsk_umem__delete(self.umem);
        }
    }
}
