pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
pub const XDP_FLAGS_HW_MODE: u32 = 1 << 3;

pub const XDP_COPY: u32 = 1 << 1;
pub const XDP_ZEROCOPY: u32 = 1 << 2;
pub const XDP_USE_NEED_WAKEUP: u32 = 1 << 3;
pub const XDP_USE_SG: u32 = 1 << 4;

pub const AF_XDP_RESERVED: u64 = 256;
