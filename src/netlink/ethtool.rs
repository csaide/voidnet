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
