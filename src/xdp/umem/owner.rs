#[cfg(feature = "async")]
use std::os::fd::RawFd;
use std::{
    marker::PhantomData,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[cfg(feature = "async")]
use libxdp_sys::xsk_umem__fd;
use libxdp_sys::{xsk_umem, xsk_umem__delete};
use memmap2::MmapMut;

use crate::xdp::{
    flags::AF_XDP_RESERVED,
    frame::{Frame, FrameBuffer},
};

/// The owner of a UMEM, this is used to create frames and is responsible for cleaning up the UMEM once all is said and done. It is also the memory
/// anchor for the frames in the UMEM, all frames are backed by the memory owned by this instance. The embedded lifetime will end up being that of the
/// calling scope of the main thread that creates the initial Umem.
pub struct UmemOwner<'umem> {
    umem: *mut xsk_umem,
    mmap: Arc<MmapMut>,
    frame_size: usize,
    num_frames: usize,
    init: AtomicBool,
    #[cfg(feature = "async")]
    fd: RawFd,

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
            mmap,
            frame_size,
            num_frames,
            init: AtomicBool::new(false),
            #[cfg(feature = "async")]
            fd: unsafe { xsk_umem__fd(umem) },
            _lifetime: PhantomData,
        }
    }

    /// Creates a new frame from the given address, length, and is fragment flag.
    #[inline(always)]
    pub(crate) fn to_frame(&self, addr: u64, len: usize, is_fragment: bool) -> Frame<'umem> {
        debug_assert!(len <= self.frame_size, "len is greater than the frame size");
        debug_assert!(
            addr + self.frame_size as u64 - AF_XDP_RESERVED <= self.mmap.len() as u64,
            "addr + frame size is greater than the mmap length: {} + {} > {}",
            addr,
            self.frame_size,
            self.mmap.len()
        );

        Frame::new(
            addr,
            // SAFETY: The address is valid because it is from the mmap and kernel guarantees it is valid, our assertions guarantee the addr/length are valid.
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.mmap.as_ptr().add(addr as usize) as *mut u8,
                    self.frame_size - AF_XDP_RESERVED as usize,
                )
            },
            len,
            is_fragment,
        )
    }

    /// Returns the file descriptor of the umem.
    #[cfg(feature = "async")]
    #[inline(always)]
    pub(crate) fn fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the pointer to the umem.
    #[inline(always)]
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
                .map(|i| {
                    self.to_frame(
                        i as u64 * self.frame_size as u64 + AF_XDP_RESERVED,
                        0,
                        false,
                    )
                })
                .collect(),
        )
    }

    /// Returns the number of frames in the UMEM.
    #[inline(always)]
    pub fn num_frames(&self) -> usize {
        self.num_frames
    }

    /// Returns the size of the frames in the UMEM.
    #[inline(always)]
    pub fn frame_size(&self) -> usize {
        self.frame_size
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::context::XdpContext;
    use crate::xdp::frame::BasicFrameBuffer;
    use crate::xdp::umem::Umem;
    use std::thread;

    fn create_umem<'umem>(
        num_frames: usize,
        frame_size: usize,
    ) -> (XdpContext, Arc<UmemOwner<'umem>>) {
        let ctx = XdpContext::new_no_init().unwrap();
        let (owner, _fq, _cq) = Umem::builder()
            .num_frames(num_frames)
            .frame_size(frame_size)
            .fill_ring_size(num_frames as u32)
            .completion_ring_size(num_frames as u32)
            .build()
            .expect("UMEM creation failed")
            .split();
        (ctx, owner)
    }

    #[test]
    fn test_init_buffer() {
        let (_, owner) = create_umem(4, 2048);

        // First call succeeds
        let buffer: BasicFrameBuffer<'_> = owner.init_buffer().unwrap();
        assert_eq!(buffer.num_frames(), 4);

        // Verify frame properties
        for (i, frame) in buffer.iter_frames().enumerate() {
            assert_eq!(frame.addr(), (i as u64) * 2048 + AF_XDP_RESERVED);
            assert_eq!(frame.len(), 0);
            assert_eq!(frame.capacity(), 2048 - AF_XDP_RESERVED as usize);
            assert!(!frame.is_fragment());
        }

        // Subsequent calls return None (one-shot)
        assert!(owner.init_buffer::<BasicFrameBuffer<'_>>().is_none());
    }

    #[test]
    fn test_to_frame() {
        let (_, owner) = create_umem(4, 4096);

        // Test non-zero len and is_fragment=true (not covered by init_buffer)
        let frame = owner.to_frame(4096, 1500, true);

        assert_eq!(frame.addr(), 4096);
        assert_eq!(frame.len(), 1500);
        assert!(frame.is_fragment());
        assert_eq!(frame.capacity(), 4096 - AF_XDP_RESERVED as usize);
    }

    #[test]
    fn test_frame_memory() {
        let (_, owner) = create_umem(2, 4096);
        let mut buffer: BasicFrameBuffer<'_> = owner.init_buffer().unwrap();

        // Write different data to each frame
        for (i, frame) in buffer.iter_frames_mut().enumerate() {
            frame.copy_from(&[i as u8; 4]);
        }

        // Verify isolation: each frame retains its own data
        for (i, frame) in buffer.iter_frames().enumerate() {
            assert_eq!(&frame[..], &[i as u8; 4]);
        }
    }

    #[test]
    fn test_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<UmemOwner<'static>>();
    }

    #[test]
    fn test_concurrent_init_buffer() {
        let (_, owner) = create_umem(4, 4096);

        let results: Vec<bool> = (0..4)
            .map(|_| {
                let o = owner.clone();
                thread::spawn(move || o.init_buffer::<BasicFrameBuffer<'_>>().is_some())
            })
            .map(|h| h.join().unwrap())
            .collect();

        assert_eq!(results.iter().filter(|&&x| x).count(), 1);
    }
}
