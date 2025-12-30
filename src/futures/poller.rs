use std::{ffi::c_int, ptr::null_mut, task::Waker};

use dashmap::{DashMap, Entry};
use errno::errno;
use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN, EPOLLOUT, epoll_create1,
    epoll_ctl, epoll_event, epoll_wait,
};

use super::error::{Error, Result};

pub struct Poller {
    poll_fd: c_int,
    max_events: usize,
    wakers: DashMap<u64, Waker>,
}

impl Poller {
    pub fn new(max_events: usize) -> Result<Self> {
        let poll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if poll_fd < 0 {
            return Err(Error::EpollCreate(errno()));
        }
        Ok(Self {
            poll_fd,
            max_events,
            wakers: DashMap::new(),
        })
    }

    pub fn register_socket(&self, fd: c_int) -> Result<()> {
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

    pub fn deregister_socket(&self, fd: c_int) -> Result<()> {
        let ret = unsafe { epoll_ctl(self.poll_fd, EPOLL_CTL_DEL, fd, null_mut()) };
        if ret < 0 {
            return Err(Error::EpollCtl(errno()));
        }
        Ok(())
    }

    pub fn register_waker(&self, fd: c_int, waker: &Waker) {
        match self.wakers.entry(fd as u64) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().clone_from(&waker);
            }
            Entry::Vacant(entry) => {
                entry.insert(waker.clone());
            }
        }
    }

    pub fn poll(&self) -> Result<()> {
        let mut events = Vec::with_capacity(self.max_events);
        loop {
            let n =
                unsafe { epoll_wait(self.poll_fd, events.as_mut_ptr(), self.max_events as i32, 0) };
            if n < 0 {
                return Err(Error::EpollWait(errno()));
            }

            unsafe { events.set_len(n as usize) };
            for event in events.drain(..) {
                if let Some((_, waker)) = self.wakers.remove(&event.u64) {
                    waker.wake();
                }
            }
        }
    }
}
