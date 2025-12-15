use thiserror::Error;

use errno::Errno;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed while opening XDP program: {0}")]
    OpenProgram(Errno),
    #[error("failed while attaching XDP program: {0}")]
    AttachProgram(Errno),
    #[error("failed while detaching XDP program: {0}")]
    DetachProgram(Errno),
    #[error("failed while finding map: {0}")]
    FindMap(Errno),
    #[error("program already attached")]
    ProgramAlreadyAttached,
    #[error("failed while updating map element: {0}")]
    UpdateMapElement(Errno),
    #[error("failed to find specified interface")]
    InterfaceNotFound,
    #[error("failed while getting map element: {0}")]
    GetMapElement(Errno),
    #[error("failed while creating umem: {0}")]
    CreateUmem(Errno),
    #[error("failed while allocating mmap for umem: {0}")]
    MmapAllocate(std::io::Error),
    #[error("umem frame stack is full")]
    StackFull,
    #[error("failed while waking fill queue: {0}")]
    WakeFillQueue(Errno),
    #[error("failed while waking tx queue: {0}")]
    TxQueueWake(Errno),
    #[error("would block")]
    WouldBlock,
    #[error("failed while creating socket: {0}")]
    CreateSocket(Errno),
}
