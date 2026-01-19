use std::ptr::null_mut;

use errno::errno;
use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN, EPOLLOUT, epoll_create1,
    epoll_ctl, epoll_event, epoll_wait,
};

use crate::xdp::error::{Error, Result};

const MAX_EVENTS: usize = 1024;

pub struct Poller {
    poll_fd: i32,
    events: [epoll_event; MAX_EVENTS],
}

impl Poller {
    pub fn new() -> Result<Self> {
        let poll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if poll_fd < 0 {
            return Err(Error::EpollCreate(errno()));
        }

        Ok(Self {
            poll_fd,
            events: [epoll_event { events: 0, u64: 0 }; MAX_EVENTS],
        })
    }

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

    pub fn deregister(&self, fd: i32) -> Result<()> {
        let ret = unsafe { epoll_ctl(self.poll_fd, EPOLL_CTL_DEL, fd, null_mut()) };
        if ret < 0 {
            return Err(Error::EpollCtl(errno()));
        }
        Ok(())
    }

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
