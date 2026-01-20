use std::ops::{Deref, DerefMut};

/// A frame is a contiguous memory region that is used to store data for a packet, this is a simple wrapper around a pointer to a MMAP'd memory region.
#[derive(Debug)]
pub struct Frame<'umem> {
    addr: u64,
    len: usize,
    data: &'umem mut [u8],
    is_fragment: bool,
}

/// SAFETY: Frame is thread safe because it is pointing to a MMAP'd memory region that is guaranteed to be valid for the lifetime of the supplied 'umem lifetime.
unsafe impl<'umem> Send for Frame<'umem> {}

impl<'umem> Frame<'umem> {
    /// Create a new frame with the given address, data pointer, length, and capacity.
    pub(crate) fn new(addr: u64, data: &'umem mut [u8], len: usize, is_fragment: bool) -> Self {
        assert!(
            data.len() > 0 && len <= data.len(),
            "len must be less than or equal to capacity, which must be greater than 0"
        );

        Self {
            addr,
            len,
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
        self.data.len()
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
    pub fn copy_from<I: AsRef<[u8]>>(&mut self, incoming: I) {
        let incoming = incoming.as_ref();

        assert!(
            self.data.len() >= incoming.len(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_new() {
        let mut data = [0u8; 100];
        let frame = Frame::new(123, &mut data, 50, false);

        assert_eq!(frame.addr(), 123);
        assert_eq!(frame.len(), 50);
        assert_eq!(frame.capacity(), 100);
        assert!(!frame.is_fragment());
    }

    #[test]
    #[should_panic(expected = "len must be less than or equal to capacity")]
    fn test_frame_new_invalid_len() {
        let mut data = [0u8; 10];
        // len (11) > capacity (10)
        let _ = Frame::new(0, &mut data, 11, false);
    }

    #[test]
    #[should_panic(expected = "len must be less than or equal to capacity")]
    fn test_frame_new_empty_data() {
        let mut data = [];
        // capacity is 0
        let _ = Frame::new(0, &mut data, 0, false);
    }

    #[test]
    fn test_frame_set_fragment() {
        let mut data = [0u8; 10];
        let mut frame = Frame::new(0, &mut data, 5, false);
        assert!(!frame.is_fragment());
        frame.set_fragment(true);
        assert!(frame.is_fragment());
    }

    #[test]
    fn test_frame_copy_from() {
        let mut data = [0u8; 10];
        let mut frame = Frame::new(0, &mut data, 0, false);

        let incoming = [1, 2, 3, 4, 5];
        frame.copy_from(&incoming);

        assert_eq!(frame.len(), 5);
        assert_eq!(&frame[..], &incoming);
    }

    #[test]
    #[should_panic(expected = "incoming data length is greater than the frame capacity")]
    fn test_frame_copy_from_overflow() {
        let mut data = [0u8; 5];
        let mut frame = Frame::new(0, &mut data, 0, false);

        let incoming = [1, 2, 3, 4, 5, 6];
        frame.copy_from(&incoming);
    }

    #[test]
    fn test_frame_deref() {
        let mut data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let frame = Frame::new(0, &mut data, 5, false);

        // Should only see first 5 bytes
        assert_eq!(frame.len(), 5);
        assert_eq!(&*frame, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_frame_deref_mut() {
        let mut data = [0u8; 10];
        let mut frame = Frame::new(0, &mut data, 5, false);

        frame[0] = 42;
        frame[4] = 99;

        assert_eq!(data[0], 42);
        assert_eq!(data[4], 99);
        assert_eq!(data[5], 0); // Outside of len
    }
}
