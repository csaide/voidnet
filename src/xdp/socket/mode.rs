use std::str::FromStr;

use crate::xdp::{
    error::{Error, Result},
    flags::{XDP_COPY, XDP_FLAGS_DRV_MODE, XDP_FLAGS_HW_MODE, XDP_FLAGS_SKB_MODE, XDP_ZEROCOPY},
    program::AttachMode,
};

#[derive(Debug, Default, Clone, Copy)]
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

#[derive(Debug, Default, Clone, Copy)]
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
