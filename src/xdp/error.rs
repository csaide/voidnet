//! XDP error handling types and helpers.

use errno::Errno;
use libxdp_sys::libxdp_strerror;
use thiserror::Error;

/// A simple [`std::result::Result`] type alias for the result type of the XDP subsystem, this is used to simplify the error handling code.
pub type Result<T> = std::result::Result<T, Error>;

/// A simple [`std::result::Result`] type alias for non-blocking operations to use, that doesn't require any cost in the error case.
pub type NonBlocking<T> = std::result::Result<T, WouldBlock>;

/// Overall XDP subsystem error type, these errors are generally returned on creation or initialization of the various components in the XDP subsystem.
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed while finding map: {0}")]
    FindMap(Errno),
    #[error("failed while getting map info: {0}")]
    GetMapInfo(Errno),
    #[error("failed while updating map element: {0}")]
    UpdateMapElement(Errno),
    #[error("failed to find specified interface")]
    InterfaceNotFound,
    #[error("failed while converting interface name to index: {0}")]
    InterfaceNameToIndex(std::ffi::NulError),
    #[error("failed while converting map name to C string: {0}")]
    InvalidMapName(std::ffi::NulError),
    #[error("failed while opening XDP program: {0}: {1}")]
    OpenProgram(Errno, String),
    #[error("failed while attaching XDP program: {0}")]
    AttachProgram(Errno),
    #[error("failed while waking fill queue: {0}")]
    WakeFillQueue(Errno),
    #[error("failed while waking tx queue: {0}")]
    WakeTxQueue(Errno),
    #[error("failed while allocating mmap for umem: {0}")]
    MmapAllocate(std::io::Error),
    #[error(
        "failed to create umem: invalid frame size: {0}: must be a power of 2 or unaligned must be enabled"
    )]
    InvalidFrameSize(usize),
    #[error("failed while creating umem: invalid fill ring size: {0}: must be a power of 2")]
    InvalidFillRingSize(u32),
    #[error("failed while creating umem: invalid completion ring size: {0}: must be a power of 2")]
    InvalidCompletionRingSize(u32),
    #[error("failed while creating umem: {0}")]
    CreateUmem(Errno),
    #[error("failed while creating socket: {0}")]
    CreateSocket(Errno),
    #[error("failed while setting socket option: {0}")]
    SetSocketOption(Errno),
    #[error("invalid attach mode: {0}")]
    InvalidAttachMode(String),
    #[error("invalid copy mode: {0}")]
    InvalidCopyMode(String),
    #[error("failed while setting XDP frags support: {0}")]
    SetXdpFragsSupport(Errno),
    #[error("failed while querying for XDP features: {0}")]
    QueryXdpFeatures(Errno),
    #[error("failed while getting MTU: {0}")]
    GetMtu(String),
    #[error("failed to query checksum offload capabilities: {0}")]
    GetChecksumOffload(String),
    #[error("failed to query queue count: {0}")]
    GetQueueCount(String),
    #[error("queue ID {0} exceeds xsks_map max_entries (2048)")]
    QueueIdOutOfRange(u32),
    #[error("fragmentation not supported by the network interface")]
    FragmentationNotSupported,
    #[error("zero copy not supported by the network interface")]
    ZeroCopyNotSupported,
    #[error("failed to poll poller: {0}")]
    PollPoller(#[from] std::io::Error),
    #[error("failed to create epoll instance: {0}")]
    EpollCreate(Errno),
    #[error("failed to wait on epoll instance: {0}")]
    EpollWait(Errno),
    #[error("failed to register file descriptor with epoll instance: {0}")]
    EpollCtl(Errno),
    #[error("{0}")]
    Other(String),
    #[error("Exiting runtime")]
    ExitRuntime,
}

/// A simple ZST error variant for would block scenarios, this is explicitly a ZST to avoid the allocations and eventual drop calls of the error case.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("network I/O error: would block")]
pub struct WouldBlock;

/// A helper function to get the error message from the XDP subsystem, this is used to simplify the error handling code.
#[cfg(target_arch = "aarch64")]
pub fn get_xdp_error_message(err: i32) -> String {
    let mut buf = [0; 1024];
    unsafe { libxdp_strerror(err, buf.as_mut_ptr(), buf.len()) };
    let nul_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..nul_pos]).to_string()
}

/// A helper function to get the error message from the XDP subsystem, this is used to simplify the error handling code.
#[cfg(target_arch = "x86_64")]
pub fn get_xdp_error_message(err: i32) -> String {
    let mut buf = [0i8; 1024];
    unsafe { libxdp_strerror(err, buf.as_mut_ptr(), buf.len()) };
    let nul_pos = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());

    // So x86_64 decided to make their c_char type an i8, so we have to convert here....
    let buf = buf[..nul_pos].iter().map(|c| *c as u8).collect::<Vec<u8>>();
    String::from_utf8_lossy(&buf).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_error_variants() {
        let e = Error::InterfaceNotFound;
        assert_eq!(e.to_string(), "failed to find specified interface");

        let e = Error::FragmentationNotSupported;
        assert_eq!(
            e.to_string(),
            "fragmentation not supported by the network interface"
        );

        let e = Error::ZeroCopyNotSupported;
        assert_eq!(
            e.to_string(),
            "zero copy not supported by the network interface"
        );

        let e = Error::ExitRuntime;
        assert_eq!(e.to_string(), "Exiting runtime");

        let e = Error::InvalidFrameSize(3000);
        assert!(e.to_string().contains("3000"));

        let e = Error::InvalidFillRingSize(7);
        assert!(e.to_string().contains("7"));

        let e = Error::InvalidCompletionRingSize(5);
        assert!(e.to_string().contains("5"));

        let e = Error::InvalidAttachMode("bad".to_string());
        assert!(e.to_string().contains("bad"));

        let e = Error::InvalidCopyMode("bad".to_string());
        assert!(e.to_string().contains("bad"));

        let e = Error::Other("custom error".to_string());
        assert_eq!(e.to_string(), "custom error");

        let e = Error::GetMtu("eth0 failed".to_string());
        assert!(e.to_string().contains("eth0 failed"));

        let e = Error::GetChecksumOffload("not supported".to_string());
        assert!(e.to_string().contains("not supported"));

        let e = Error::GetQueueCount("not supported".to_string());
        assert!(e.to_string().contains("not supported"));

        let e = Error::QueueIdOutOfRange(3000);
        assert!(e.to_string().contains("3000"));
    }

    #[test]
    fn display_would_block() {
        let e = WouldBlock;
        assert_eq!(e.to_string(), "network I/O error: would block");
    }

    #[test]
    fn would_block_equality() {
        assert_eq!(WouldBlock, WouldBlock);
    }
}
