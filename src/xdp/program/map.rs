use std::os::raw::c_void;

use errno::errno;
use libxdp_sys::{bpf_map, bpf_map__fd, bpf_map_update_elem};

use crate::xdp::error::{Error, Result};

pub struct Map {
    map: *mut bpf_map,
}

impl Map {
    pub fn new(map: *mut bpf_map) -> Self {
        Self { map }
    }

    pub fn as_mut_ptr(&mut self) -> *mut bpf_map {
        self.map
    }

    pub fn as_ptr(&self) -> *const bpf_map {
        self.map
    }

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
