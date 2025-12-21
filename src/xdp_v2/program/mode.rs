/// The mode in which the XDP program should be attached to the network interface.
#[derive(Debug, Default, Clone, Copy)]
#[repr(u32)]
pub enum AttachMode {
    #[default]
    Unspec = 0,
    Native = 1,
    Skb = 2,
    Hw = 3,
}
