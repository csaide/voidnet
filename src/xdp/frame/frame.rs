use std::ops::{Deref, DerefMut};

/// A frame is a contiguous memory region that is used to store data for a packet, this is a simple wrapper around a pointer to a MMAP'd memory region.
#[derive(Debug)]
pub struct Frame<'umem> {
    addr: u64,
    len: usize,
    capacity: usize,
    data: &'umem mut [u8],
    is_fragment: bool,
}

unsafe impl<'umem> Send for Frame<'umem> {}

impl<'umem> Frame<'umem> {
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
        data: &'umem mut [u8],
        len: usize,
        capacity: usize,
        is_fragment: bool,
    ) -> Self {
        debug_assert!(
            capacity > 0 && len <= capacity,
            "len must be less than or equal to capacity, which must be greater than 0"
        );

        Self {
            addr,
            len,
            capacity,
            data,
            is_fragment,
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
    pub fn set_fragment(&mut self, is_fragment: bool) {
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
        unsafe {
            std::ptr::copy_nonoverlapping(incoming.as_ptr(), self.data.as_mut_ptr(), self.len)
        };
    }
}

impl<'umem> Deref for Frame<'umem> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data[..self.len]
    }
}

impl<'umem> DerefMut for Frame<'umem> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data[..self.len]
    }
}
