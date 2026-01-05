use std::str::FromStr;

use libxdp_sys::{
    xdp_attach_mode_XDP_MODE_HW, xdp_attach_mode_XDP_MODE_NATIVE, xdp_attach_mode_XDP_MODE_SKB,
    xdp_attach_mode_XDP_MODE_UNSPEC,
};

use crate::xdp::error::{Error, Result};

/// The mode in which the XDP program should be attached to the network interface. This is a wrapper around the [xdp_attach_mode] enum.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AttachMode {
    /// The unspecified mode. This is the default mode.
    #[default]
    Unspec = xdp_attach_mode_XDP_MODE_UNSPEC,
    /// The native mode. This is the mode that is used when the XDP program is attached to the network interface using the native API.
    Native = xdp_attach_mode_XDP_MODE_NATIVE,
    /// The skb mode. This is the mode that is used when the XDP program is attached to the network interface using the skb API.
    Skb = xdp_attach_mode_XDP_MODE_SKB,
    /// The hw mode. This is the mode that is used when the XDP program is attached to the network interface using the hw API.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attach_mode_default() {
        assert_eq!(AttachMode::default(), AttachMode::Unspec);
    }

    #[test]
    fn test_attach_mode_from_str() {
        assert_eq!(AttachMode::from_str("unspec").unwrap(), AttachMode::Unspec);
        assert_eq!(AttachMode::from_str("native").unwrap(), AttachMode::Native);
        assert_eq!(AttachMode::from_str("skb").unwrap(), AttachMode::Skb);
        assert_eq!(AttachMode::from_str("hw").unwrap(), AttachMode::Hw);
    }

    #[test]
    fn test_attach_mode_from_str_invalid() {
        let result = AttachMode::from_str("invalid");
        assert!(result.is_err());
        match result.err().unwrap() {
            Error::InvalidAttachMode(s) => assert_eq!(s, "invalid"),
            _ => panic!("Expected InvalidAttachMode error"),
        }
    }

    #[test]
    fn test_attach_mode_discriminants() {
        assert_eq!(AttachMode::Unspec as u32, xdp_attach_mode_XDP_MODE_UNSPEC);
        assert_eq!(AttachMode::Native as u32, xdp_attach_mode_XDP_MODE_NATIVE);
        assert_eq!(AttachMode::Skb as u32, xdp_attach_mode_XDP_MODE_SKB);
        assert_eq!(AttachMode::Hw as u32, xdp_attach_mode_XDP_MODE_HW);
    }
}
