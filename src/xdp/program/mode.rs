use std::str::FromStr;

use libxdp_sys::{
    xdp_attach_mode_XDP_MODE_HW, xdp_attach_mode_XDP_MODE_NATIVE, xdp_attach_mode_XDP_MODE_SKB,
    xdp_attach_mode_XDP_MODE_UNSPEC,
};

use crate::xdp::error::{Error, Result};

/// The mode in which the XDP program should be attached to the network interface.
#[derive(Debug, Default, Clone, Copy)]
#[repr(u32)]
pub enum AttachMode {
    #[default]
    Unspec = xdp_attach_mode_XDP_MODE_UNSPEC,
    Native = xdp_attach_mode_XDP_MODE_NATIVE,
    Skb = xdp_attach_mode_XDP_MODE_SKB,
    Hw = xdp_attach_mode_XDP_MODE_HW,
}

impl FromStr for AttachMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "unspec" => Ok(AttachMode::Unspec),
            "native" => Ok(AttachMode::Native),
            "skb" => Ok(AttachMode::Skb),
            "hw" => Ok(AttachMode::Hw),
            _ => Err(Error::InvalidAttachMode(s.to_string())),
        }
    }
}
