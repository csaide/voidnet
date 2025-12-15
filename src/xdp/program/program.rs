use std::{ffi::CString, os::raw::c_void, ptr::null};

use errno::errno;
use libc::if_nametoindex;
use libxdp_sys::{
    bpf_object__find_map_by_name, bpf_object__open_mem, libxdp_get_error, libxdp_strerror,
    xdp_program, xdp_program__attach, xdp_program__bpf_obj, xdp_program__close,
    xdp_program__detach, xdp_program__from_bpf_obj,
};

use crate::xdp::{
    error::{Error, Result},
    program::Map,
};

pub struct XdpProgram {
    program: *mut xdp_program,
    attached: Option<i32>,
}

impl XdpProgram {
    pub fn new(data: &[u8]) -> Result<Self> {
        println!("Opening program from data: {}", data.len());
        let object =
            unsafe { bpf_object__open_mem(data.as_ptr() as *const c_void, data.len(), null()) };

        let err = unsafe { libxdp_get_error(object as *const _) };
        if err < 0 {
            return Err(Error::OpenProgram(errno()));
        }

        let program = unsafe { xdp_program__from_bpf_obj(object, null()) };
        let err = unsafe { libxdp_get_error(program as *const _) };
        if err < 0 {
            return Err(Error::OpenProgram(errno()));
        }

        Ok(Self {
            program,
            attached: None,
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

    pub fn detach(&mut self) -> Result<()> {
        if let Some(attached) = self.attached.take() {
            let err = unsafe { xdp_program__detach(self.program, attached, 0, 0) };
            if err < 0 {
                return Err(Error::DetachProgram(errno()));
            }
        }
        Ok(())
    }

    pub fn attach(&mut self, if_name: &str) -> Result<()> {
        if self.attached.is_some() {
            return Err(Error::ProgramAlreadyAttached);
        }

        let if_name_c = CString::new(if_name).unwrap();
        let if_index = unsafe { if_nametoindex(if_name_c.as_ptr()) } as i32;
        if if_index == 0 {
            return Err(Error::InterfaceNotFound);
        }

        println!(
            "Attaching program to interface: {} (index: {}) -> {}",
            if_name,
            if_index,
            self.program.is_null()
        );
        let err = unsafe { xdp_program__attach(self.program, if_index, 0, 0) };
        if err < 0 {
            let mut buf = [0; 2048];
            let n = unsafe { libxdp_strerror(-1 * err, buf.as_mut_ptr(), buf.len()) };
            println!(
                "Failed to attach program to interface: {} (index: {}): {}",
                if_name,
                if_index,
                unsafe { CString::from_vec_unchecked(buf[..n as usize].to_vec()) }
                    .into_string()
                    .unwrap()
            );
            return Err(Error::AttachProgram(errno()));
        }

        self.attached = Some(if_index);

        Ok(())
    }
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        let _ = self.detach();

        unsafe {
            xdp_program__close(self.program);
        }
    }
}
