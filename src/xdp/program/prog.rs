use std::{ffi::CString, os::raw::c_void, ptr::null};

use errno::errno;
use libc::if_nametoindex;
use libxdp_sys::{
    bpf_map__fd, bpf_map_get_info_by_fd, bpf_map_info, bpf_object__find_map_by_name,
    bpf_object__open_mem, bpf_xdp_query, bpf_xdp_query_opts, libxdp_get_error, xdp_program,
    xdp_program__attach, xdp_program__bpf_obj, xdp_program__close, xdp_program__detach,
    xdp_program__from_bpf_obj, xdp_program__set_xdp_frags_support,
};

use crate::{
    netlink::{get_checksum_offload, get_mtu},
    xdp::error::{Error, Result, get_xdp_error_message},
};

use super::{AttachMode, Map, XdpInfo};

/// A wrapper around a raw [xdp_program] object, this exposes a safe API for creating and attaching XDP programs.
pub struct XdpProgram {
    program: *mut xdp_program,
    if_index: i32,
    attach_mode: AttachMode,
    info: XdpInfo,
}

// SAFETY: Send safe because the only reason its not is because of the included `*mut xdp_program` however this is managed by the kernel, and guaranteed to
// live until we are dropped.
unsafe impl Send for XdpProgram {}

impl XdpProgram {
    /// Creates a new [XdpProgram] object from the given data, and then attaches that program to the given network interface with the given attach mode.
    pub fn new(
        data: &[u8],
        if_name: &str,
        attach_mode: AttachMode,
        enable_fragmentation: bool,
    ) -> Result<Self> {
        let if_name_c = match CString::new(if_name) {
            Ok(c) => c,
            Err(e) => return Err(Error::InterfaceNameToIndex(e)),
        };

        let if_index = unsafe { if_nametoindex(if_name_c.as_ptr()) } as i32;
        if if_index == 0 {
            return Err(Error::InterfaceNotFound);
        }

        let data_ptr = data.as_ptr() as *const c_void;
        let object = unsafe { bpf_object__open_mem(data_ptr, data.len(), null()) };
        let err = unsafe { libxdp_get_error(object as *const _) };
        if err < 0 {
            return Err(Error::OpenProgram(
                errno(),
                get_xdp_error_message(err as i32),
            ));
        }

        let program = unsafe { xdp_program__from_bpf_obj(object, null()) };
        let err = unsafe { libxdp_get_error(program as *const _) };
        if err < 0 {
            return Err(Error::OpenProgram(
                errno(),
                get_xdp_error_message(err as i32),
            ));
        }

        // Note this has no effect for hardware that doesn't support fragmentation.
        let err = unsafe { xdp_program__set_xdp_frags_support(program, enable_fragmentation) };
        if err < 0 {
            return Err(Error::SetXdpFragsSupport(errno()));
        }

        let err = unsafe { xdp_program__attach(program, if_index, attach_mode as u32, 0) };
        if err < 0 {
            return Err(Error::AttachProgram(errno()));
        }

        let mut info = XdpInfo::default();
        let err =
            unsafe { bpf_xdp_query(if_index, 0, &mut info as *mut _ as *mut bpf_xdp_query_opts) };
        if err < 0 {
            return Err(Error::QueryXdpFeatures(errno()));
        }

        info.mtu = get_mtu(if_index)?;

        let (rx_offload, tx_offload) = get_checksum_offload(if_index)?;
        info.rx_offload = rx_offload;
        info.tx_offload = tx_offload;

        Ok(Self {
            program,
            if_index,
            attach_mode,
            info,
        })
    }

    #[cfg(test)]
    pub fn new_no_init() -> Result<Self> {
        Ok(Self {
            program: std::ptr::null_mut(),
            if_index: 0,
            attach_mode: AttachMode::default(),
            info: XdpInfo::default(),
        })
    }

    /// Returns a mutable pointer to the raw [xdp_program] object.
    pub fn as_mut_ptr(&mut self) -> *mut xdp_program {
        self.program
    }

    /// Returns a constant pointer to the raw [xdp_program] object.
    pub fn as_ptr(&self) -> *const xdp_program {
        self.program
    }

    /// Returns the attach mode of the program.
    pub fn attach_mode(&self) -> AttachMode {
        self.attach_mode
    }

    /// Returns the information about the XDP program.
    pub fn info(&self) -> &XdpInfo {
        &self.info
    }

    /// Finds a map by name in the program.
    pub fn find_map(&self, name: &str) -> Result<Map> {
        let name = match CString::new(name) {
            Ok(c) => c,
            Err(e) => return Err(Error::InvalidMapName(e)),
        };
        let map = unsafe {
            bpf_object__find_map_by_name(xdp_program__bpf_obj(self.program), name.as_ptr())
        };
        let err = unsafe { libxdp_get_error(map as *const _) };
        if err < 0 {
            return Err(Error::FindMap(errno()));
        }

        let map_fd = unsafe { bpf_map__fd(map as *const _) };

        let mut info: bpf_map_info = unsafe { std::mem::zeroed() };
        let mut info_len = std::mem::size_of::<bpf_map_info>() as u32;
        let err = unsafe { bpf_map_get_info_by_fd(map_fd, &mut info, &mut info_len) };
        if err < 0 {
            return Err(Error::GetMapInfo(errno()));
        }
        Ok(Map::new(map, info))
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

#[cfg(test)]
mod tests {
    use super::*;

    // `XdpProgram::new()` is the only constructor for real programs.  The two
    // error paths that can be triggered without real BPF/XDP infrastructure are:
    //
    // 1. An interface name containing a NUL byte — `CString::new` fails and
    //    `Error::InterfaceNameToIndex` is returned before any kernel call.
    // 2. A syntactically valid but nonexistent interface name — `if_nametoindex`
    //    returns 0 and `Error::InterfaceNotFound` is returned before any BPF
    //    object is opened.
    //
    // All paths beyond those two require a real BPF object and a real network
    // interface, so they are skipped here.

    #[test]
    fn new_rejects_null_byte_in_interface_name() {
        let result = XdpProgram::new(b"", "eth\x000", AttachMode::Skb, false);
        assert!(
            matches!(result, Err(Error::InterfaceNameToIndex(_))),
            "expected InterfaceNameToIndex error"
        );
    }

    #[test]
    fn new_rejects_nonexistent_interface() {
        let result = XdpProgram::new(b"", "voidnet_no_such_iface_xyz", AttachMode::Skb, false);
        assert!(
            matches!(result, Err(Error::InterfaceNotFound)),
            "expected InterfaceNotFound error"
        );
    }
}
