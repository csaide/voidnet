use std::ptr::null_mut;

use errno::errno;
use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN, EPOLLOUT, epoll_create1,
    epoll_ctl, epoll_event, epoll_wait,
};

use crate::xdp::error::{Error, Result};

const MAX_EVENTS: usize = 1024;

/// A poller designed to work with the [LocalExecutor] executor.
///
/// This poller wraps epoll on linux to provide a simple and efficient network I/O polling solution to drive I/O futures.
///
/// [LocalExecutor]: crate::xdp::futures::local::LocalExecutor
pub struct Poller {
    poll_fd: i32,
    events: [epoll_event; MAX_EVENTS],
}

impl Poller {
    /// Creates a new poller. This will call `epoll_create1` with the `EPOLL_CLOEXEC` flag to create a new epoll file descriptor.
    pub(crate) fn new() -> Result<Self> {
        let poll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if poll_fd < 0 {
            return Err(Error::EpollCreate(errno()));
        }

        Ok(Self {
            poll_fd,
            events: [epoll_event { events: 0, u64: 0 }; MAX_EVENTS],
        })
    }

    /// Registers a new file descriptor with the poller. This will automatically register for both EPOLLIN and EPOLLOUT events.
    ///
    /// The [Poller] operates under edge triggered semantics, so its important to ensure that resources are exhausted before polling again.
    pub fn register(&self, fd: i32) -> Result<()> {
        let mut event = epoll_event {
            events: (EPOLLIN | EPOLLOUT | EPOLLET) as u32,
            u64: fd as u64,
        };

        let ret = unsafe { epoll_ctl(self.poll_fd, EPOLL_CTL_ADD, fd, &mut event) };
        if ret < 0 {
            return Err(Error::EpollCtl(errno()));
        }
        Ok(())
    }

    /// Deregisters a file descriptor from the poller. This will remove the file descriptor from the poller's event loop.
    pub fn deregister(&self, fd: i32) -> Result<()> {
        let ret = unsafe { epoll_ctl(self.poll_fd, EPOLL_CTL_DEL, fd, null_mut()) };
        if ret < 0 {
            return Err(Error::EpollCtl(errno()));
        }
        Ok(())
    }

    /// Polls the poller for new events. This will block for up to the given timeout duration.
    ///
    /// If no events are ready before the timeout duration, this will return `false`.
    /// If events are ready, this will return `true`.
    ///
    /// If an error occurs, this will return an error.
    pub fn poll(&mut self, timeout_ms: i32) -> Result<bool> {
        let n = unsafe {
            epoll_wait(
                self.poll_fd,
                self.events.as_mut_ptr() as *mut epoll_event,
                MAX_EVENTS as i32,
                timeout_ms,
            )
        };

        if n == 0 {
            return Ok(false);
        }
        if n < 0 {
            return Err(Error::EpollWait(errno()));
        }

        Ok(true)
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        // Close the poll fd to avoid leaking it.
        unsafe { libc::close(self.poll_fd) };
    }
}
