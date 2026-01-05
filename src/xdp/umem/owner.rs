use std::{
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use libxdp_sys::{xsk_umem, xsk_umem__delete, xsk_umem__fd};
use memmap2::MmapMut;

use crate::xdp::frame::{Frame, FrameBuffer};

/// The owner of a UMEM, this is used to create frames and is responsible for cleaning up the UMEM once all is said and done. It is also the memory
/// anchor for the frames in the UMEM, all frames are backed by the memory owned by this instance. The embedded lifetime will end up being that of the
/// calling scope of the main thread that creates the initial Umem.
pub struct UmemOwner<'umem> {
    umem: *mut xsk_umem,
    fd: i32,
    mmap: Arc<MmapMut>,
    frame_size: usize,
    num_frames: usize,
    init: AtomicBool,

    // Ok so some explanation here, to make sure our Frame's can't outlive the actual memory that is backing them we need some lifetime to use. That said
    // we are going to end up being wrapped in an Arc which will lose all concept of lifetimes for its references as it should. So to get around this
    // problem we embed the lifetime we need to have the frames live for here. In practice this will end up being pinned to the lifetime of the calling
    // scope of the main thread that creates the initial Umem.
    _lifetime: PhantomData<&'umem ()>,
}

// SAFETY: UmemOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Send for UmemOwner<'umem> {}

// SAFETY: UmemOwner is thread safe because it is immutable. And the only non-send/sync fields are owned by the kernel and guaranteed to be valid.
unsafe impl<'umem> Sync for UmemOwner<'umem> {}

impl<'umem> UmemOwner<'umem> {
    pub(crate) fn new(
        umem: *mut xsk_umem,
        mmap: Arc<MmapMut>,
        frame_size: usize,
        num_frames: usize,
    ) -> Self {
        Self {
            umem,
            fd: unsafe { xsk_umem__fd(umem) },
            mmap,
            frame_size,
            num_frames,
            init: AtomicBool::new(false),
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn fd(&self) -> i32 {
        self.fd
    }

    pub(crate) fn to_frame(&self, addr: u64, len: usize, is_fragment: bool) -> Frame<'umem> {
        debug_assert!(len <= self.frame_size, "len is greater than the frame size");
        debug_assert!(
            addr + len as u64 <= self.mmap.len() as u64,
            "addr + len is greater than the mmap length"
        );

        Frame::new(
            addr,
            // SAFETY: The address is valid because it is from the mmap and kernel guarantees it is valid, our assertions guarantee the addr/length are valid.
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.mmap.as_ptr().add(addr as usize) as *mut u8,
                    self.frame_size,
                )
            },
            len,
            is_fragment,
        )
    }

    pub(crate) fn as_ptr(&self) -> *mut xsk_umem {
        self.umem
    }

    /// Initialize the frame buffer with the frames from the UMEM, its then up to the caller what to do with these frames, you can push them into the fill queue, use them
    /// for writing packets, or some combination of the two. This can only be called once on the [UmemOwner] instance, and will return None on every subsequent call.
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
