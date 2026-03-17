use std::io::Cursor;

use neli::{
    FromBytesWithInput, Size,
    consts::{
        genl::{Cmd, NlAttrType},
        nl::NlmF,
        socket::NlFamily,
    },
    genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, NlattrBuilder},
    neli_enum,
    nl::NlPayload,
    router::synchronous::NlRouter,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

use crate::xdp::error::{self, Error};

/// Ethtool generic netlink command IDs (from linux/ethtool_netlink.h).
#[neli_enum(serialized_type = "u8")]
pub enum EthtoolCmd {
    FeaturesGet = 11,
    ChannelsGet = 17,
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

/// Ethtool CHANNELS request/reply attributes (from linux/ethtool_netlink.h).
#[neli_enum(serialized_type = "u16")]
pub enum EthtoolAttrChannels {
    Unspec = 0,
    Header = 1,
    RxMax = 2,
    TxMax = 3,
    OtherMax = 4,
    CombinedMax = 5,
    RxCount = 6,
    TxCount = 7,
    OtherCount = 8,
    CombinedCount = 9,
}
impl NlAttrType for EthtoolAttrChannels {}

/// Queries the ethtool generic netlink interface to determine whether RX and TX
/// checksum offloading are enabled for the given network interface.
///
/// Returns `(rx_offload, tx_offload)` where each is `true` if the corresponding
/// checksum offload is active on the hardware.
pub fn get_checksum_offload(if_index: i32) -> error::Result<(bool, bool)> {
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

/// Queries the ethtool generic netlink interface to determine the number of
/// combined RX/TX queues for the given network interface.
///
/// Returns the combined channel count. If the query fails (e.g., the driver
/// does not support it, or the interface is virtual), returns `Ok(1)` as a
/// safe default.
pub fn get_queue_count(if_index: i32) -> error::Result<u32> {
    // Use neli only for family resolution, then raw socket I/O for the
    // CHANNELS_GET request/response. neli's typed attribute deserialization
    // misparses responses that mix nested and flat attributes at the same level.
    let (router, _) = match NlRouter::connect(NlFamily::Generic, None, Groups::empty()) {
        Ok(r) => r,
        Err(_) => return Ok(1),
    };

    let family_id: u16 = match router.resolve_genl_family("ethtool") {
        Ok(id) => id,
        Err(_) => return Ok(1),
    };

    // Build the request manually as raw bytes.
    // nlattr: DevIndex (type=1, nested=false, len=8, payload=if_index)
    let dev_index_attr = {
        let mut buf = Vec::new();
        buf.extend_from_slice(&8u16.to_ne_bytes()); // nla_len
        buf.extend_from_slice(&1u16.to_ne_bytes()); // nla_type = ETHTOOL_A_HEADER_DEV_INDEX
        buf.extend_from_slice(&(if_index as u32).to_ne_bytes());
        buf
    };

    // nlattr: Header (type=1|NLA_F_NESTED, len=4+dev_index_attr.len())
    let header_attr = {
        let nla_len = (4 + dev_index_attr.len()) as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&nla_len.to_ne_bytes());
        buf.extend_from_slice(&(1u16 | 0x8000).to_ne_bytes()); // type=1, NLA_F_NESTED
        buf.extend_from_slice(&dev_index_attr);
        // NLA padding
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        buf
    };

    // genlmsghdr: cmd=17 (CHANNELS_GET), version=1, reserved=0
    let genlhdr = [17u8, 1, 0, 0];

    // nlmsghdr
    let total_len = 16 + genlhdr.len() + header_attr.len();
    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&(total_len as u32).to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&family_id.to_ne_bytes()); // nlmsg_type
    msg.extend_from_slice(&1u16.to_ne_bytes()); // nlmsg_flags = NLM_F_REQUEST
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
    msg.extend_from_slice(&genlhdr);
    msg.extend_from_slice(&header_attr);

    // Send via raw netlink socket.
    let sock = {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                16, // NETLINK_GENERIC
            )
        };
        if fd < 0 {
            return Ok(1);
        }
        let addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut addr = addr;
        addr.nl_family = libc::AF_NETLINK as u16;
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Ok(1);
        }
        fd
    };

    let sent = unsafe { libc::send(sock, msg.as_ptr() as *const _, msg.len(), 0) };
    if sent < 0 {
        unsafe { libc::close(sock) };
        return Ok(1);
    }

    let mut recv_buf = [0u8; 4096];
    let received = unsafe { libc::recv(sock, recv_buf.as_mut_ptr() as *mut _, recv_buf.len(), 0) };
    unsafe { libc::close(sock) };

    if received < 20 {
        return Ok(1);
    }
    let received = received as usize;

    // Parse the response: skip nlmsghdr (16 bytes) + genlmsghdr (4 bytes).
    let raw = &recv_buf[20..received];

    let mut combined_count: u32 = 0;
    let mut rx_count: u32 = 0;
    let mut tx_count: u32 = 0;

    let mut off = 0usize;
    while off + 4 <= raw.len() {
        let nla_len = u16::from_ne_bytes([raw[off], raw[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([raw[off + 2], raw[off + 3]]);
        if nla_len < 4 {
            break;
        }
        let attr_type = nla_type & 0x3FFF;
        // Only read non-nested u32 attrs (nla_len == 8 = 4-byte header + 4-byte payload).
        if nla_len == 8 && off + 8 <= raw.len() {
            let val = u32::from_ne_bytes(raw[off + 4..off + 8].try_into().unwrap());
            // 0xFFFFFFFF means "not applicable" in ethtool (displayed as "n/a").
            if val != u32::MAX {
                match attr_type {
                    9 => combined_count = val, // CombinedCount
                    6 => rx_count = val,       // RxCount
                    7 => tx_count = val,       // TxCount
                    _ => {}
                }
            }
        }
        // Advance by NLA-aligned length.
        off += (nla_len + 3) & !3;
    }
    // Prefer combined count; fall back to rx or tx count; default to 1.
    let count = if combined_count > 0 {
        combined_count
    } else if rx_count > 0 {
        rx_count
    } else if tx_count > 0 {
        tx_count
    } else {
        1
    };

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_queue_count_on_loopback() {
        let count = get_queue_count(1).expect("query should not error");
        assert!(count >= 1, "queue count should be at least 1");
    }

    #[test]
    fn get_queue_count_on_eth0() {
        // eth0 on this machine has 1 combined queue per `ethtool -l eth0`.
        let idx = unsafe { libc::if_nametoindex(c"eth0".as_ptr() as *const _) };
        if idx == 0 {
            return; // eth0 doesn't exist, skip.
        }
        let count = get_queue_count(idx as i32).expect("query should not error");
        assert_eq!(count, 1, "eth0 should have 1 combined queue");
    }

    #[test]
    fn get_queue_count_on_invalid_interface() {
        let count = get_queue_count(999999).expect("query should not error");
        assert_eq!(count, 1, "should default to 1 for invalid interface");
    }
}
