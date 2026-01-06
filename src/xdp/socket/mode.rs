use std::str::FromStr;

use crate::xdp::{
    error::{Error, Result},
    flags::{XDP_COPY, XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_SKB_MODE, XDP_ZEROCOPY},
    program::AttachMode,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BindMode {
    #[default]
    Skb = XDP_FLAGS_SKB_MODE,
    Driver = XDP_FLAGS_DRV_MODE,
    Hw = XDP_FLAGS_HW_MODE,
}

impl From<AttachMode> for BindMode {
    fn from(mode: AttachMode) -> Self {
        match mode {
            AttachMode::Unspec | AttachMode::Skb => BindMode::Skb,
            AttachMode::Native => BindMode::Driver,
            AttachMode::Hw => BindMode::Hw,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CopyMode {
    #[default]
    Copy = XDP_COPY,
    ZeroCopy = XDP_ZEROCOPY,
}

impl FromStr for CopyMode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "copy" => Ok(CopyMode::Copy),
            "zero-copy" => Ok(CopyMode::ZeroCopy),
            _ => Err(Error::InvalidCopyMode(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_mode_default_and_discriminants() {
        assert_eq!(BindMode::default(), BindMode::Skb);

        // Verify discriminants match kernel ABI flags
        assert_eq!(BindMode::Skb as u32, XDP_FLAGS_SKB_MODE);
        assert_eq!(BindMode::Driver as u32, XDP_FLAGS_DRV_MODE);
        assert_eq!(BindMode::Hw as u32, XDP_FLAGS_HW_MODE);
    }

    #[test]
    fn test_bind_mode_from_attach_mode() {
        let cases = [
            (AttachMode::Unspec, BindMode::Skb),
            (AttachMode::Skb, BindMode::Skb),
            (AttachMode::Native, BindMode::Driver),
            (AttachMode::Hw, BindMode::Hw),
        ];
        for (attach, expected) in cases {
            assert_eq!(BindMode::from(attach), expected);
        }
    }

    #[test]
    fn test_copy_mode_default_and_discriminants() {
        assert_eq!(CopyMode::default(), CopyMode::Copy);

        // Verify discriminants match kernel ABI flags
        assert_eq!(CopyMode::Copy as u32, XDP_COPY);
        assert_eq!(CopyMode::ZeroCopy as u32, XDP_ZEROCOPY);
    }

    #[test]
    fn test_copy_mode_from_str_valid() {
        assert_eq!("copy".parse::<CopyMode>().unwrap(), CopyMode::Copy);
        assert_eq!("zero-copy".parse::<CopyMode>().unwrap(), CopyMode::ZeroCopy);
    }

    #[test]
    fn test_copy_mode_from_str_invalid() {
        // Invalid inputs: wrong case, typos, whitespace, empty
        let invalid = ["Copy", "ZERO-COPY", "zerocopy", " copy", "copy ", ""];
        for input in invalid {
            let err = CopyMode::from_str(input).unwrap_err();
            assert!(
                matches!(&err, Error::InvalidCopyMode(s) if s == input),
                "Expected InvalidCopyMode({:?}), got {:?}",
                input,
                err
            );
        }
    }
}
