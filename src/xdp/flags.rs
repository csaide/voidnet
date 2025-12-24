pub const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
pub const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
pub const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
pub const XDP_FLAGS_HW_MODE: u32 = 1 << 3;
pub const XDP_FLAGS_REPLACE: u32 = 1 << 4;
pub const XDP_FLAGS_MODES: u32 = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE;
pub const XDP_FLAGS_MASK: u32 = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE;

/* Options for the sxdp_flags field */
pub const XDP_SHARED_UMEM: u32 = 1 << 0;
pub const XDP_COPY: u32 = 1 << 1;
pub const XDP_ZEROCOPY: u32 = 1 << 2;
/* If this option is set, the driver might go sleep and in that case
 * the XDP_RING_NEED_WAKEUP flag in the fill and/or Tx rings will be
 * set. If it is set, the application need to explicitly wake up the
 * driver with a poll() (Rx and Tx) or sendto() (Tx only). If you are
 * running the driver and the application on the same core, you should
 * use this option so that the kernel will yield to the user space
 * application.
 */
pub const XDP_USE_NEED_WAKEUP: u32 = 1 << 3;
/* By setting this option, userspace application indicates that it can
 * handle multiple descriptors per packet thus enabling AF_XDP to split
 * multi-buffer XDP frames into multiple Rx descriptors. Without this set
 * such frames will be dropped.
 */
pub const XDP_USE_SG: u32 = 1 << 4;
