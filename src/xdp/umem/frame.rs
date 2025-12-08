use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{Error, Result};

/// A frame contains a contiguous memory region that is split into two sections:
/// - The first section is the overhead section, which is used to store the metadata for the frame.
/// - The second section is the data section, which is used to store the data for the frame.
///
/// The overhead section is fixed size and is used to store the metadata for the frame.
/// The data section is variable size and is used to store the data for the frame.
///
/// The overhead section is 256 bytes by default, but can be configured to be any size.
///
/// The data section is the remaining space in the frame.
#[derive(Debug)]
pub struct Frame<'a> {
    addr: u64,
    len: usize,
    data: &'a mut [u8],
}

impl<'a> Frame<'a> {
    /// Create a new empty frame contrainer for using the UMEM memory in userspace. This is meant to wrap a
    /// contiguous memory region of size `capacity` in the UMEM memory in userspace.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `capacity`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `capacity`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address offset of the UMEM memory in userspace.
    /// * `ptr` - The pointer to the UMEM memory in userspace.
    /// * `capacity` - The capacity of the UMEM memory in userspace.
    ///
    /// # Returns
    ///
    /// A new frame contrainer for using the UMEM memory in userspace. Which can be dereferenced as a slice of bytes.
    pub unsafe fn new(addr: u64, ptr: *mut u8, capacity: usize) -> Self {
        let data = unsafe { std::slice::from_raw_parts_mut(ptr, capacity) };
        Self { addr, len: 0, data }
    }

    /// Create a new frame contrainer for using the UMEM memory in userspace. This is meant to wrap a
    /// contiguous memory region of size `len` in the UMEM memory in userspace.
    ///
    /// # Safety
    ///
    /// This function does not check if the address is valid or if it points to a contiguous memory
    /// region of size `len`. It is the responsibility of the caller to ensure that the address is valid
    /// and that the pointer points to a contiguous memory region of size `len`.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address offset of the UMEM memory in userspace.
    /// * `ptr` - The pointer to the UMEM memory in userspace.
    /// * `len` - The length of the frame in bytes.
    /// * `capacity` - The capacity of the UMEM memory in userspace.
    ///
    /// # Returns
    ///
    /// A new frame contrainer for using the UMEM memory in userspace. Which can be dereferenced as a slice of bytes.
    pub unsafe fn new_with_len(addr: u64, ptr: *mut u8, len: usize, capacity: usize) -> Self {
        debug_assert!(
            len <= capacity,
            "len must be less than or equal to capacity"
        );
        let data = unsafe { std::slice::from_raw_parts_mut(ptr, capacity) };
        Self { addr, len, data }
    }

    /// Returns the address offset of the UMEM memory in userspace.
    pub fn addr(&self) -> u64 {
        self.addr
    }

    /// Returns the overall capacity of the frame in bytes.
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    /// Returns the current length of the frame in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the frame is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Clears the frame by setting the length to 0.
    ///
    /// NOTE: This does not zero the underlying memory region.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }

    pub fn set_len(&mut self, len: usize) {
        self.len = len;
    }

    /// Copies a value into the frame.
    ///
    /// # Arguments
    ///
    /// * `value` - The value to copy into the frame.
    ///
    /// # Returns
    ///
    /// Ok(()) if the value was copied successfully, Err(Error) otherwise.
    ///
    /// # Errors
    ///
    /// Returns Err(Error::ValueTooLarge) if the value is too large to fit in the frame.
    pub fn copy_into<T: IntoBytes + Immutable + KnownLayout>(&mut self, value: T) -> Result<()> {
        let bytes = value.as_bytes();
        if bytes.len() > self.capacity() {
            return Err(Error::ValueTooLarge);
        }

        self.data[..bytes.len()].copy_from_slice(&bytes);
        self.len = bytes.len();
        Ok(())
    }

    /// Retrieve a reference to the value stored in the frame.
    pub fn get<T: FromBytes + Immutable + KnownLayout>(&self) -> Result<&T> {
        FromBytes::ref_from_prefix(&self.data[..self.len])
            .map(|(value, _)| value)
            .map_err(|e| Error::InvalidByteSequence(e.to_string()))
    }

    /// Retrieve a mutable reference to the value stored in the frame.
    pub fn get_mut<T: FromBytes + IntoBytes + KnownLayout>(&mut self) -> Result<&mut T> {
        FromBytes::mut_from_prefix(&mut self.data[..self.len])
            .map(|(value, _)| value)
            .map_err(|e| Error::InvalidByteSequence(e.to_string()))
    }
}
