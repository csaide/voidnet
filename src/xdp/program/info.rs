pub const NETDEV_XDP_ACT_BASIC: u64 = 1;
pub const NETDEV_XDP_ACT_REDIRECT: u64 = 2;
pub const NETDEV_XDP_ACT_NDO_XMIT: u64 = 4;
pub const NETDEV_XDP_ACT_XSK_ZEROCOPY: u64 = 8;
pub const NETDEV_XDP_ACT_HW_OFFLOAD: u64 = 16;
pub const NETDEV_XDP_ACT_RX_SG: u64 = 32;
pub const NETDEV_XDP_ACT_NDO_XMIT_SG: u64 = 64;

#[repr(C)]
pub struct XdpInfo {
    pub sz: u32,
    pub prog_id: u32,
    pub drv_prog_id: u32,
    pub hw_prog_id: u32,
    pub skb_prog_id: u32,
    pub attach_mode: u8,
    pub feature_flags: u64,
    pub xdp_zc_max_segs: u32,
    pub mtu: u32,
}

impl XdpInfo {
    pub fn basic_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_BASIC != 0
    }

    pub fn redirect_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_REDIRECT != 0
    }

    pub fn ndo_xmit_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_NDO_XMIT != 0
    }

    pub fn xsk_zero_copy_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_XSK_ZEROCOPY != 0
    }

    pub fn hw_offload_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_HW_OFFLOAD != 0
    }

    pub fn fragmentation_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_RX_SG != 0
    }

    pub fn ndo_xmit_fragmentation_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_NDO_XMIT_SG != 0
    }

    pub fn max_fragments(&self) -> u32 {
        self.xdp_zc_max_segs
    }
}

impl Default for XdpInfo {
    fn default() -> Self {
        let mut us: XdpInfo = unsafe { std::mem::zeroed() };
        us.sz = std::mem::size_of::<XdpInfo>() as u32;
        us
    }
}

impl std::fmt::Debug for XdpInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Features {
            basic: bool,
            redirect: bool,
            ndo_xmit: bool,
            xsk_zero_copy: bool,
            hw_offload: bool,
            fragmentation: bool,
            ndo_xmit_fragmentation: bool,
        }

        let features = Features {
            basic: self.basic_support(),
            redirect: self.redirect_support(),
            ndo_xmit: self.ndo_xmit_support(),
            xsk_zero_copy: self.xsk_zero_copy_support(),
            hw_offload: self.hw_offload_support(),
            fragmentation: self.fragmentation_support(),
            ndo_xmit_fragmentation: self.ndo_xmit_fragmentation_support(),
        };

        f.debug_struct("XdpInfo")
            .field("prog_id", &self.prog_id)
            .field("drv_prog_id", &self.drv_prog_id)
            .field("hw_prog_id", &self.hw_prog_id)
            .field("skb_prog_id", &self.skb_prog_id)
            .field("attach_mode", &self.attach_mode)
            .field("max_fragments", &self.xdp_zc_max_segs)
            .field("mtu", &self.mtu)
            .field("features", &features)
            .finish()
    }
}

impl std::fmt::Display for XdpInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
