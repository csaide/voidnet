use std::{ffi::CString, io::Cursor, os::raw::c_void, ptr::null};

use errno::errno;
use libc::if_nametoindex;
use libxdp_sys::{
    bpf_map__fd, bpf_map_get_info_by_fd, bpf_map_info, bpf_object__find_map_by_name,
    bpf_object__open_mem, bpf_xdp_query, bpf_xdp_query_opts, libxdp_get_error, xdp_program,
    xdp_program__attach, xdp_program__bpf_obj, xdp_program__close, xdp_program__detach,
    xdp_program__from_bpf_obj, xdp_program__set_xdp_frags_support,
};
use neli::{
    FromBytesWithInput, Size,
    consts::{
        nl::NlmF,
        rtnl::{Ifla, RtAddrFamily, Rtm},
        socket::NlFamily,
    },
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    nl::NlPayload,
    router::synchronous::NlRouter,
    rtnl::{Ifinfomsg, IfinfomsgBuilder},
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

use crate::xdp::error::{Error, Result, get_xdp_error_message};

use super::{AttachMode, Map, XdpInfo};

/// Ethtool generic netlink constants defined in a submodule to avoid conflicts
/// with the crate-level `Result` type alias that the `neli_enum` proc macro
/// generated code would otherwise resolve to.
mod ethtool_nl {
    use neli::{
        consts::genl::{Cmd, NlAttrType},
        neli_enum,
    };

    /// Ethtool generic netlink command IDs (from linux/ethtool_netlink.h).
    #[neli_enum(serialized_type = "u8")]
    pub enum EthtoolCmd {
        FeaturesGet = 11,
    }
    impl Cmd for EthtoolCmd {}

    /// Ethtool FEATURES request/reply attributes.
    #[neli_enum(serialized_type = "u16")]
    pub enum EthtoolAttrFeatures {
        Unspec = 0,
        Header = 1,
        Hw = 2,
        Wanted = 3,
        Active = 4,
        Nochange = 5,
    }
    impl NlAttrType for EthtoolAttrFeatures {}

    /// Ethtool request header attributes.
    #[neli_enum(serialized_type = "u16")]
    pub enum EthtoolAttrHeader {
        Unspec = 0,
        DevIndex = 1,
        DevName = 2,
        Flags = 3,
    }
    impl NlAttrType for EthtoolAttrHeader {}

    /// Bitset container attributes.
    #[neli_enum(serialized_type = "u16")]
    pub enum EthtoolAttrBitset {
        Unspec = 0,
        Nomask = 1,
        Size = 2,
        Bits = 3,
        Value = 4,
        Mask = 5,
    }
    impl NlAttrType for EthtoolAttrBitset {}

    /// Bitset bits array attributes.
    #[neli_enum(serialized_type = "u16")]
    pub enum EthtoolAttrBitsetBits {
        Unspec = 0,
        Bit = 1,
    }
    impl NlAttrType for EthtoolAttrBitsetBits {}

    /// Individual bitset bit attributes.
    #[neli_enum(serialized_type = "u16")]
    pub enum EthtoolAttrBitsetBit {
        Unspec = 0,
        Index = 1,
        Name = 2,
        Value = 3,
    }
    impl NlAttrType for EthtoolAttrBitsetBit {}
}
use ethtool_nl::*;

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

fn get_mtu(if_index: i32) -> Result<u32> {
    let (rtnl, _) = NlRouter::connect(NlFamily::Route, None, Groups::empty())
        .map_err(|e| Error::GetMtu(e.to_string()))?;

    let ifinfomsg = IfinfomsgBuilder::default()
        .ifi_family(RtAddrFamily::Netlink)
        .ifi_index(if_index)
        .build()
        .map_err(|e| Error::GetMtu(e.to_string()))?;

    let recv = rtnl
        .send::<_, _, Rtm, Ifinfomsg>(
            Rtm::Getlink,
            NlmF::DUMP_FILTERED | NlmF::REQUEST,
            NlPayload::Payload(ifinfomsg),
        )
        .map_err(|e| Error::GetMtu(e.to_string()))?;

    for response in recv {
        let mut response = response.map_err(|e| Error::GetMtu(e.to_string()))?;
        if let Some(payload) = response.get_payload() {
            return payload
                .rtattrs()
                .get_attr_handle()
                .get_attr_payload_as::<u32>(Ifla::Mtu)
                .map_err(|e| Error::GetMtu(e.to_string()));
        }
        if let Some(err) = response.get_err() {
            return Err(Error::GetMtu(err.to_string()));
        }
    }
    Err(Error::GetMtu(format!("Interface {} not found", if_index)))
}

/// Queries the ethtool generic netlink interface to determine whether RX and TX
/// checksum offloading are enabled for the given network interface.
///
/// Returns `(rx_offload, tx_offload)` where each is `true` if the corresponding
/// checksum offload is active on the hardware.
fn get_checksum_offload(if_index: i32) -> Result<(bool, bool)> {
    let (router, _) = NlRouter::connect(NlFamily::Generic, None, Groups::empty())
        .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

    let family_id = router
        .resolve_genl_family("ethtool")
        .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

    // Build nested header with the device interface index.
    let header_attrs: GenlBuffer<EthtoolAttrHeader, Buffer> = [NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(EthtoolAttrHeader::DevIndex)
                .build()
                .map_err(|e| Error::GetChecksumOffload(e.to_string()))?,
        )
        .nla_payload(if_index as u32)
        .build()
        .map_err(|e| Error::GetChecksumOffload(e.to_string()))?]
    .into_iter()
    .collect();

    // Build the FEATURES_GET request with the nested header.
    let attrs: GenlBuffer<EthtoolAttrFeatures, Buffer> = [NlattrBuilder::default()
        .nla_type(
            AttrTypeBuilder::default()
                .nla_type(EthtoolAttrFeatures::Header)
                .nla_nested(true)
                .build()
                .map_err(|e| Error::GetChecksumOffload(e.to_string()))?,
        )
        .nla_payload(header_attrs)
        .build()
        .map_err(|e| Error::GetChecksumOffload(e.to_string()))?]
    .into_iter()
    .collect();

    let msg = GenlmsghdrBuilder::default()
        .cmd(EthtoolCmd::FeaturesGet)
        .version(1)
        .attrs(attrs)
        .build()
        .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

    let recv = router
        .send::<_, _, u16, Genlmsghdr<EthtoolCmd, EthtoolAttrFeatures>>(
            family_id,
            NlmF::REQUEST,
            NlPayload::Payload(msg),
        )
        .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

    let mut rx_offload = false;
    let mut tx_offload = false;

    for response in recv {
        let mut response = response.map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

        if let Some(payload) = response.get_payload() {
            let features_handle = payload.attrs().get_attr_handle();

            // Parse the ACTIVE features bitset (verbose format with named bits).
            let active_handle = features_handle
                .get_nested_attributes::<EthtoolAttrBitset>(EthtoolAttrFeatures::Active)
                .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

            // Get the BITS array within the bitset.
            let bits_handle = active_handle
                .get_nested_attributes::<EthtoolAttrBitsetBits>(EthtoolAttrBitset::Bits)
                .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;

            // Iterate through each BIT entry looking for checksum features.
            for bit_attr in bits_handle.iter() {
                let payload = bit_attr.nla_payload();
                let nested = GenlBuffer::<EthtoolAttrBitsetBit, Buffer>::from_bytes_with_input(
                    &mut Cursor::new(payload.as_ref()),
                    payload.unpadded_size(),
                )
                .map_err(|e| Error::GetChecksumOffload(e.to_string()))?;
                let bit_handle = nested.get_attr_handle();

                if let Some(name_attr) = bit_handle.get_attribute(EthtoolAttrBitsetBit::Name) {
                    let name_bytes = name_attr.nla_payload().as_ref();
                    let name = std::str::from_utf8(
                        name_bytes.split(|&b| b == 0).next().unwrap_or(name_bytes),
                    )
                    .unwrap_or("");

                    match name {
                        "rx-checksum" => rx_offload = true,
                        "tx-checksum-ip-generic" => tx_offload = true,
                        _ => {}
                    }
                }
            }
        }

        if let Some(err) = response.get_err() {
            return Err(Error::GetChecksumOffload(err.to_string()));
        }
    }

    Ok((rx_offload, tx_offload))
}
