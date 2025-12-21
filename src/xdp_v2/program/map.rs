use std::os::raw::c_void;

use errno::errno;
use libxdp_sys::{bpf_map, bpf_map__fd, bpf_map_update_elem};

use crate::xdp_v2::error::{Error, Result};

/// A wrapper around a raw [bpf_map] object, this exposes a safe API for setting values in a BPF map.
pub struct Map {
    map: *mut bpf_map,
}

impl Map {
    /// Wraps a raw [bpf_map] object, this is the only way to create a new [Map] object.
    pub fn new(map: *mut bpf_map) -> Self {
        Self { map }
    }

    /// Returns a mutable pointer to the raw [bpf_map] object.
    pub fn as_mut_ptr(&mut self) -> *mut bpf_map {
        self.map
    }

    /// Returns a constant pointer to the raw [bpf_map] object.
    pub fn as_ptr(&self) -> *const bpf_map {
        self.map
    }

    /// Updates the value of an element in the map with the given key and value.
    pub fn update_elem<K, V>(&self, key: &K, value: &V) -> Result<()> {
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
