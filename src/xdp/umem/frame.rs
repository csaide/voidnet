use std::{
    ops::{Deref, DerefMut},
    rc::Rc,
};

use super::ThreadLocalFrameStack;

/// A frame is a contiguous memory region that is used to store data for a packet, this is a simple wrapper around a pointer to a MMAP'd memory region.
#[derive(Debug)]
pub struct Frame {
    addr: u64,
    len: usize,
    capacity: usize,
    data: *mut u8,
    frame_stack: Rc<ThreadLocalFrameStack>,
}

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
        data: *mut u8,
        len: usize,
        capacity: usize,
        frame_stack: Rc<ThreadLocalFrameStack>,
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
            frame_stack,
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

    /// Copies the data from the incoming slice into the frame.
    ///
    /// # Safety
    ///
    /// This function does not check if the incoming slice like thing will fit in the frame, it also
    /// doesn't check if the incoming slice is valid in any way. We blindly copy data into the frame.
    #[inline]
    pub unsafe fn copy_from(&mut self, incoming: &[u8]) {
        debug_assert!(
            self.capacity >= incoming.len(),
            "frame must be full to copy from"
        );

        self.len = incoming.len();
        unsafe { std::ptr::copy_nonoverlapping(incoming.as_ptr(), self.data, self.len) };
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        let _ = self.frame_stack.push(self.addr);
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
