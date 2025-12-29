use errno::Errno;
use thiserror::Error;

/// A simple type alias for the result type of the XDP subsystem, this is used to simplify the error handling code.
pub type Result<T> = std::result::Result<T, Error>;

/// Overall XDP subsystem error type, these errors are generally returned on creation or initialization of the various components in the XDP subsystem.
#[derive(Error, Debug)]
pub enum Error {
    #[error("failed while finding map: {0}")]
    FindMap(Errno),
    #[error("failed while updating map element: {0}")]
    UpdateMapElement(Errno),
    #[error("failed to find specified interface")]
    InterfaceNotFound,
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
}

/// A simple ZST error variant for would block scenarios, this is explicitly a ZST to avoid the allocations and eventual drop calls of the error case.
#[derive(Debug, Error)]
#[error("network I/O error: would block")]
pub struct WouldBlock;

/// A simple type alias for non-blocking operations to use, that doesn't require any cost in the error case.
pub type NonBlocking<T> = std::result::Result<T, WouldBlock>;
