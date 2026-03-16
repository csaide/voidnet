use std::os::raw::c_void;

use errno::errno;
use libxdp_sys::{bpf_map, bpf_map__fd, bpf_map_info, bpf_map_update_elem};

use crate::xdp::error::{Error, Result};

/// A wrapper around a raw [bpf_map] object, this exposes a mostly safe API for setting values in a BPF map.
///
/// We left the update_elem function unsafe because maps are a bit hard to fully map to a type safe variant. There are cases,
/// such as the `.bss` map, where the values could be different types depending on the static data in the BPF program. Generally,
/// keys are always the same type, and some variant of an integer type.
pub struct Map {
    map: *mut bpf_map,
    info: bpf_map_info,
    name: String,
}

// SAFETY: Send safe because the only reason its not is because of the included `*mut bpf_map` however this is managed by the kernel
// and guaranteed to not move until we are dropped by our parent [XdpProgram] which is the true owner of the map.
unsafe impl Send for Map {}

impl Map {
    /// Wraps a raw [bpf_map] and its corresponding [bpf_map_info] object.
    pub fn new(map: *mut bpf_map, info: bpf_map_info) -> Self {
        #[cfg(target_arch = "aarch64")]
        let name = String::from_utf8_lossy(&info.name[..]).to_string();

        #[cfg(target_arch = "x86_64")]
        let name =
            String::from_utf8_lossy(&info.name[..].iter().map(|c| *c as u8).collect::<Vec<u8>>())
                .to_string();
        Self { map, info, name }
    }

    /// Returns the name of the map.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a mutable pointer to the raw [bpf_map] object.
    pub fn as_mut_ptr(&mut self) -> *mut bpf_map {
        self.map
    }

    /// Returns a constant pointer to the raw [bpf_map] object.
    pub fn as_ptr(&self) -> *const bpf_map {
        self.map
    }

    /// Returns the information about the map.
    pub fn info(&self) -> &bpf_map_info {
        &self.info
    }

    /// Updates an element in the map at the given key with the given value.
    ///
    /// A few notes for those not familiar with BPF maps:
    /// - The value supplied is bitwise copied into the map by the kernel via the pointer provided (reference).
    /// - There is no "type" for the key or value here everything is done based on size and then binary comparisons/copy.
    /// - That isn't to say its safe to use the _wrong_ type either, see the safety section below.
    ///
    /// # Safety
    ///
    /// It is the responsibility of the caller to ensure that the key and value are the correct size and type for the map.
    ///
    /// This will panic in debug builds if the key or value are not the correct size for the map, but we can't enforce type checks here
    /// always confirm the types you are using are correct, for the map you are using.
    pub unsafe fn update_elem<K, V>(&self, key: &K, value: &V) -> Result<()>
    where
        K: Sized + Copy,
        V: Sized + Copy,
    {
        let ret = unsafe {
            bpf_map_update_elem(
                bpf_map__fd(self.map),
                key as *const _ as *const c_void,
                value as *const _ as *const c_void,
                0,
            )
        };
        if ret < 0 {
            return Err(Error::UpdateMapElement(errno()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_map() -> Map {
        let mut info: bpf_map_info = unsafe { std::mem::zeroed() };
        let bytes = b"test_map";
        for (i, &b) in bytes.iter().enumerate() {
            #[cfg(target_arch = "aarch64")]
            {
                info.name[i] = b;
            }
            #[cfg(target_arch = "x86_64")]
            {
                info.name[i] = b as i8;
            }
        }
        Map::new(std::ptr::null_mut(), info)
    }

    #[test]
    fn name_returns_map_name() {
        let map = make_test_map();
        assert!(map.name().starts_with("test_map"));
    }

    #[test]
    fn as_ptr_returns_inner() {
        let map = make_test_map();
        assert!(map.as_ptr().is_null());
    }

    #[test]
    fn as_mut_ptr_returns_inner() {
        let mut map = make_test_map();
        assert!(map.as_mut_ptr().is_null());
    }

    #[test]
    fn info_returns_info() {
        let map = make_test_map();
        let info = map.info();
        assert_eq!(info.type_, 0);
    }
}
