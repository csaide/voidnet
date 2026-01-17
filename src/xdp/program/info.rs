pub const NETDEV_XDP_ACT_BASIC: u64 = 1;
pub const NETDEV_XDP_ACT_REDIRECT: u64 = 2;
pub const NETDEV_XDP_ACT_NDO_XMIT: u64 = 4;
pub const NETDEV_XDP_ACT_XSK_ZEROCOPY: u64 = 8;
pub const NETDEV_XDP_ACT_HW_OFFLOAD: u64 = 16;
pub const NETDEV_XDP_ACT_RX_SG: u64 = 32;
pub const NETDEV_XDP_ACT_NDO_XMIT_SG: u64 = 64;

/// A wrapper around the XDP query info struct, this exposes a safe API for querying the XDP program information.
#[repr(C)]
pub struct XdpInfo {
    /// The size of the [XdpInfo] struct.
    pub sz: u32,
    /// The program ID of the XDP program. This is the ID of the XDP program as seen by the kernel.
    pub prog_id: u32,
    /// The driver program ID of the XDP program. This is the ID of the XDP program as seen by the driver.
    pub drv_prog_id: u32,
    /// The hardware program ID of the XDP program. This is the ID of the XDP program as seen by the hardware.
    pub hw_prog_id: u32,
    /// The skb program ID of the XDP program. This is the ID of the XDP program as seen by the skb.
    pub skb_prog_id: u32,
    /// The attach mode of the XDP program.
    pub attach_mode: u8,
    /// The feature flags of the XDP program.
    pub feature_flags: u64,
    /// The maximum number of segments that can be used with the XDP program.
    pub xdp_zc_max_segs: u32,
    /// The MTU of the network interface.
    ///
    /// Note this is an additional field that we use in this library, its not part of the original xdp_info struct in libxdp.
    pub mtu: u32,
}

impl XdpInfo {
    /// Returns whether the XDP program supports the basic features.
    /// This includes the ability to return XDP_PASS, XDP_DROP, and XDP_ABORTED.
    pub fn basic_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_BASIC != 0
    }

    /// Returns whether the XDP program supports the redirect feature.
    /// This includes the ability to return XDP_REDIRECT.
    pub fn redirect_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_REDIRECT != 0
    }

    /// Returns whether the XDP program supports the ndo_xmit feature.
    /// This includes the ability to redirect packets to other network interfaces.
    pub fn ndo_xmit_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_NDO_XMIT != 0
    }

    /// Returns whether the XDP program supports the xsk_zero_copy feature.
    /// This includes the ability to use zero copy mode with AF_XDP.
    pub fn xsk_zero_copy_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_XSK_ZEROCOPY != 0
    }

    /// Returns whether the XDP program supports the hw_offload feature.
    /// This includes the ability to offload XDP programs to hardware.
    pub fn hw_offload_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_HW_OFFLOAD != 0
    }

    /// Returns whether the XDP program supports the fragmentation feature.
    /// This requires scatter gather receive support in the driver.
    pub fn fragmentation_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_RX_SG != 0
    }

    /// Returns whether the XDP program supports the ndo_xmit_fragmentation feature.
    /// This requires scatter gather transmit support in the driver.
    pub fn ndo_xmit_fragmentation_support(&self) -> bool {
        self.feature_flags & NETDEV_XDP_ACT_NDO_XMIT_SG != 0
    }

    /// Returns the maximum number of fragments that can be used with the XDP program.
    pub fn max_fragments(&self) -> u32 {
        self.xdp_zc_max_segs
    }
}

impl Default for XdpInfo {
    fn default() -> Self {
        let mut us: XdpInfo = unsafe { std::mem::zeroed() };
        // We need to strip the final mtu field off this struct, since its our addition and not part of the original struct.
        us.sz = std::mem::size_of::<XdpInfo>() as u32 - std::mem::size_of::<u32>() as u32;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xdp_info_default() {
        let info = XdpInfo::default();
        assert_eq!(
            info.sz,
            std::mem::size_of::<XdpInfo>() as u32 - std::mem::size_of::<u32>() as u32
        );
        assert_eq!(info.prog_id, 0);
        assert_eq!(info.feature_flags, 0);
        assert_eq!(info.mtu, 0);
    }

    #[test]
    fn test_xdp_info_features() {
        let mut info = XdpInfo::default();

        // Initially all false
        assert!(!info.basic_support());
        assert!(!info.redirect_support());
        assert!(!info.ndo_xmit_support());
        assert!(!info.xsk_zero_copy_support());
        assert!(!info.hw_offload_support());
        assert!(!info.fragmentation_support());
        assert!(!info.ndo_xmit_fragmentation_support());

        // Set individual flags and check
        info.feature_flags |= NETDEV_XDP_ACT_BASIC;
        assert!(info.basic_support());

        info.feature_flags |= NETDEV_XDP_ACT_REDIRECT;
        assert!(info.redirect_support());

        info.feature_flags |= NETDEV_XDP_ACT_NDO_XMIT;
        assert!(info.ndo_xmit_support());

        info.feature_flags |= NETDEV_XDP_ACT_XSK_ZEROCOPY;
        assert!(info.xsk_zero_copy_support());

        info.feature_flags |= NETDEV_XDP_ACT_HW_OFFLOAD;
        assert!(info.hw_offload_support());

        info.feature_flags |= NETDEV_XDP_ACT_RX_SG;
        assert!(info.fragmentation_support());

        info.feature_flags |= NETDEV_XDP_ACT_NDO_XMIT_SG;
        assert!(info.ndo_xmit_fragmentation_support());
    }

    #[test]
    fn test_xdp_info_max_fragments() {
        let mut info = XdpInfo::default();
        info.xdp_zc_max_segs = 16;
        assert_eq!(info.max_fragments(), 16);
    }

    #[test]
    fn test_xdp_info_debug_display() {
        let mut info = XdpInfo::default();
        info.prog_id = 42;
        info.feature_flags = NETDEV_XDP_ACT_BASIC | NETDEV_XDP_ACT_REDIRECT;
        info.mtu = 1500;

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("XdpInfo"));
        assert!(debug_str.contains("prog_id: 42"));
        assert!(debug_str.contains("mtu: 1500"));
        assert!(debug_str.contains("basic: true"));
        assert!(debug_str.contains("redirect: true"));
        assert!(debug_str.contains("ndo_xmit: false"));

        let display_str = format!("{}", info);
        assert_eq!(debug_str, display_str);
    }
}
