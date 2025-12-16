use std::{ffi::CString, os::raw::c_void, ptr::null};

use errno::errno;
use libc::if_nametoindex;
use libxdp_sys::{
    bpf_object__find_map_by_name, bpf_object__open_mem, libxdp_get_error, xdp_program,
    xdp_program__attach, xdp_program__bpf_obj, xdp_program__close, xdp_program__detach,
    xdp_program__from_bpf_obj,
};

use crate::xdp::{
    error::{Error, Result},
    program::Map,
};

#[derive(Debug, Default, Clone, Copy)]
#[repr(u32)]
pub enum AttachMode {
    #[default]
    Unspec = 0,
    Native = 1,
    Skb = 2,
    Hw = 3,
}

pub struct XdpProgram {
    program: *mut xdp_program,
    if_index: i32,
    attach_mode: AttachMode,
}

impl XdpProgram {
    pub fn new(data: &[u8], if_name: &str, attach_mode: AttachMode) -> Result<Self> {
        let if_name_c = CString::new(if_name).unwrap();
        let if_index = unsafe { if_nametoindex(if_name_c.as_ptr()) } as i32;
        if if_index == 0 {
            return Err(Error::InterfaceNotFound);
        }

        let data_ptr = data.as_ptr() as *const c_void;
        let object = unsafe { bpf_object__open_mem(data_ptr, data.len(), null()) };
        let err = unsafe { libxdp_get_error(object as *const _) };
        if err < 0 {
            return Err(Error::OpenProgram(errno()));
        }

        let program = unsafe { xdp_program__from_bpf_obj(object, null()) };
        let err = unsafe { libxdp_get_error(program as *const _) };
        if err < 0 {
            return Err(Error::OpenProgram(errno()));
        }

        let err = unsafe { xdp_program__attach(program, if_index, attach_mode as u32, 0) };
        if err < 0 {
            return Err(Error::AttachProgram(errno()));
        }

        Ok(Self {
            program,
            if_index,
            attach_mode,
        })
    }

    pub fn as_mut_ptr(&mut self) -> *mut xdp_program {
        self.program
    }

    pub fn as_ptr(&self) -> *const xdp_program {
        self.program
    }

    pub fn find_map(&self, name: &str) -> Result<Map> {
        let name = CString::new(name).unwrap();
        let map = unsafe {
            bpf_object__find_map_by_name(xdp_program__bpf_obj(self.program), name.as_ptr())
        };
        let err = unsafe { libxdp_get_error(map as *const _) };
        if err < 0 {
            return Err(Error::FindMap(errno()));
        }
        Ok(Map::new(map))
    }
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        let err =
            unsafe { xdp_program__detach(self.program, self.if_index, self.attach_mode as u32, 0) };
        if err < 0 {
            eprintln!("Failed to detach program: {}", errno());
        }

        unsafe {
            xdp_program__close(self.program);
        }
    }
}
