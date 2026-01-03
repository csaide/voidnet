use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

use memmap2::MmapMut;

/// A frame is a contiguous memory region that is used to store data for a packet, this is a simple wrapper around a pointer to a MMAP'd memory region.
#[derive(Debug)]
pub struct Frame {
    addr: u64,
    len: usize,
    capacity: usize,
    data: *mut u8,
    is_fragment: bool,
    _mmap: Arc<MmapMut>, // Guarantee we can't outlive the mmap.
}

unsafe impl Send for Frame {}

impl Frame {
    /// Create a new frame with the given address, data pointer, length, and capacity.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `capacity`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `capacity`, which is fully initialized.
    ///
    /// NOTE: the data does not need to be fully 0'ed, it just must be assumed it will be read entirely and therefore must
    /// be initialized to valid u8 values for all locations.
    pub unsafe fn new(
        addr: u64,
        len: usize,
        capacity: usize,
        is_fragment: bool,
        mmap: Arc<MmapMut>,
    ) -> Self {
        debug_assert!(
            capacity > 0 && len <= capacity,
            "len must be less than or equal to capacity, which must be greater than 0"
        );
        debug_assert!(
            addr + len as u64 <= mmap.len() as u64,
            "addr + len is greater than the mmap length"
        );

        Self {
            addr,
            len,
            capacity,
            // SAFETY: this is safe because the mmap is guaranteed to be valid.
            // We also _have_ to change the pointer type from *const u8 to *mut u8 as Frame's are mutable and we need multiple of them which
            // are guaranteed to be non-overlapping, so its safe to cast it to a mutable pointer, no two callers can access the same frame address.
            data: unsafe { mmap.as_ptr().offset(addr as isize) as *mut u8 },
            is_fragment,
            _mmap: mmap,
        }
    }

    /// Returns the address offset of the UMEM memory in userspace.
    #[inline]
    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// Returns the current length of the frame in bytes.
    ///
    /// This is the number of bytes that would have been read by the kernel or written by the user.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the capacity of the frame in bytes.
    ///
    /// This is the total number of bytes that the frame can hold.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns whether the frame is a fragment.
    #[inline]
    pub fn is_fragment(&self) -> bool {
        self.is_fragment
    }

    /// Set the fragment flag for the frame.
    #[inline]
    pub unsafe fn set_fragment(&mut self, is_fragment: bool) {
        self.is_fragment = is_fragment;
    }

    /// Copies the data from the incoming slice into the frame.
    ///
    /// # Safety
    ///
    /// This function does not check if the incoming slice like thing will fit in the frame, it also
    /// doesn't check if the incoming slice is valid in any way. We blindly copy data into the frame.
    #[inline]
    pub unsafe fn copy_from<I: AsRef<[u8]>>(&mut self, incoming: I) {
        let incoming = incoming.as_ref();

        debug_assert!(
            self.capacity >= incoming.len(),
            "incoming data length is greater than the frame capacity"
        );

        self.len = incoming.len();
        unsafe { std::ptr::copy_nonoverlapping(incoming.as_ptr(), self.data, self.len) };
    }
}

impl Deref for Frame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

impl DerefMut for Frame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.data, self.len) }
    }
}
