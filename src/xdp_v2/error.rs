use errno::Errno;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed while finding map: {0}")]
    FindMap(Errno),
    #[error("failed while updating map element: {0}")]
    UpdateMapElement(Errno),
    #[error("failed to find specified interface")]
    InterfaceNotFound,
    #[error("failed while opening XDP program: {0}")]
    OpenProgram(Errno),
    #[error("failed while attaching XDP program: {0}")]
    AttachProgram(Errno),
    #[error("failed while waking fill queue: {0}")]
    WakeFillQueue(Errno),
    #[error("failed while waking tx queue: {0}")]
    WakeTxQueue(Errno),
    #[error("failed while allocating mmap for umem: {0}")]
    MmapAllocate(std::io::Error),
    #[error("failed while creating umem: {0}")]
    CreateUmem(Errno),
    #[error("failed while creating socket: {0}")]
    CreateSocket(Errno),
}
