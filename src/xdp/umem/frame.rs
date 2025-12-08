use std::ops::Deref;

use super::Result;

#[derive(Debug)]
pub struct Frame {
    addr: u64,
    len: usize,
    capacity: usize,
    data: *mut u8,
}

// SAFETY: This is safe because the frame is just a wrapper around a pointer to a MMAP'd memory region.
// these cannot move and are pinned between userspace and kernelspace.
//
// It is on the implementation to ensure that the frame is destroyed hen the MMAP'd memory region is destroyed.
unsafe impl Send for Frame {}
unsafe impl Sync for Frame {}

impl Frame {
    /// Create a new frame with the given address, data pointer, and capacity.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `capacity`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `capacity`, which is fully initialized.
    ///
    /// NOTE: the data may not need to be fully 0'ed, just must assume it will be read entirely and therefore must
    /// be initialized to valid u8 values for all locations.
    pub unsafe fn new(addr: u64, data: *mut u8, capacity: usize) -> Self {
        debug_assert!(capacity > 0, "capacity must be greater than 0");

        Self {
            addr,
            len: 0,
            capacity,
            data,
        }
    }

    /// Create a new frame with the given address, data pointer, length, and capacity.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `capacity`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `capacity`, which is fully initialized.
    ///
    /// NOTE: the data may not need to be fully 0'ed, just must assume it will be read entirely and therefore must
    /// be initialized to valid u8 values for all locations.
    pub unsafe fn new_with_len(addr: u64, data: *mut u8, len: usize, capacity: usize) -> Self {
        debug_assert!(
            capacity > 0 && len <= capacity,
            "len must be less than or equal to capacity, which must be greater than 0"
        );

        Self {
            addr,
            len,
            capacity,
            data,
        }
    }

    /// Returns the address offset of the UMEM memory in userspace.
    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// Returns the current length of the frame in bytes.
    ///
    /// This is the number of bytes that would have been read by the kernel or written by the user.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the overall capacity of the frame in bytes.
    ///
    /// This is the total available space in the frame for data.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns true if the frame is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns true if the frame is full.
    pub fn is_full(&self) -> bool {
        self.len == self.capacity
    }

    /// Clears the frame by setting the length to 0.
    ///
    /// NOTE: This does not zero the underlying memory region.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Returns a slice of the data in the frame.
    pub fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }

    /// Modifies the frame by calling the given function with a mutable slice of the data in the frame.
    ///
    /// # Arguments
    ///
    /// * `f` - The function to call with a mutable slice of the data in the frame.
    ///
    /// # Returns
    ///
    /// Ok(()) if the function was called successfully, Err(Error) otherwise if the supplied function returns an error.
    pub fn modify<F>(&mut self, f: F) -> Result<()>
    where
        F: FnOnce(&mut [u8]) -> Result<usize>,
    {
        self.len = f(unsafe { std::slice::from_raw_parts_mut(self.data, self.capacity) })?;
        Ok(())
    }

    /// Copies the data from the incoming slice into the frame.
    ///
    /// # Arguments
    ///
    /// * `incoming` - The slice to copy from.
    ///
    /// # Safety
    ///
    /// This function does not check if the incoming slice like thing will fit in the frame, it also
    /// doesn't check if the incoming slice is valid in any way. We blindly copy data into the frame.
    pub unsafe fn copy_from<D: AsRef<[u8]>>(&mut self, incoming: D) {
        let incoming = incoming.as_ref();

        debug_assert!(
            self.capacity >= incoming.len(),
            "frame must be full to copy from"
        );

        self.len = incoming.len();
        unsafe {
            std::ptr::copy_nonoverlapping(incoming.as_ptr(), self.data, self.len);
        }
    }
}

impl Deref for Frame {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.data()
    }
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}
