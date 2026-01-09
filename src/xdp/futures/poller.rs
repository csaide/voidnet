use std::{ptr::null_mut, task::Waker};

use dashmap::{DashMap, Entry};
use errno::errno;
use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN, EPOLLOUT, epoll_create1,
    epoll_ctl, epoll_event, epoll_wait,
};

use crate::xdp::error::{Error, Result};

#[derive(Default)]
enum WakerSlot {
    #[default]
    Empty,
    Waker(Waker),
    Multi(Vec<Waker>),
}

impl WakerSlot {
    pub fn new(waker: Waker) -> Self {
        Self::Waker(waker)
    }

    pub fn append(&mut self, waker: Waker) {
        match self {
            Self::Empty => *self = Self::Waker(waker),
            Self::Waker(current) => *self = Self::Multi(vec![current.clone(), waker]),
            Self::Multi(current) => current.push(waker),
        }
    }

    pub fn wake(&mut self) {
        let us = std::mem::take(self);
        match us {
            Self::Empty => (),
            Self::Waker(waker) => waker.wake(),
            Self::Multi(mut wakers) => wakers.drain(..).for_each(|waker| waker.wake()),
        }
    }
}

pub(crate) struct Poller {
    poll_fd: i32,
    timeout_ms: i32,
    max_events: usize,
    wakers: DashMap<u64, WakerSlot>,
}

impl Poller {
    pub fn new(max_events: usize, timeout_ms: i32) -> Result<Self> {
        let poll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if poll_fd < 0 {
            return Err(Error::EpollCreate(errno()));
        }

        Ok(Self {
            poll_fd,
            timeout_ms,
            max_events,
            wakers: DashMap::with_capacity(max_events),
        })
    }

    pub fn register_socket(&self, fd: i32) -> Result<()> {
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

    pub fn deregister_socket(&self, fd: i32) -> Result<()> {
        let ret = unsafe { epoll_ctl(self.poll_fd, EPOLL_CTL_DEL, fd, null_mut()) };
        if ret < 0 {
            return Err(Error::EpollCtl(errno()));
        }
        Ok(())
    }

    pub fn register_waker(&self, fd: i32, waker: &Waker) -> Result<()> {
        match self.wakers.entry(fd as u64) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().append(waker.clone());
            }
            Entry::Vacant(entry) => {
                entry.insert(WakerSlot::new(waker.clone()));
            }
        }
        Ok(())
    }

    pub fn poll(&self) -> Result<()> {
        let mut events = Vec::with_capacity(self.max_events);
        loop {
            let n = unsafe {
                epoll_wait(
                    self.poll_fd,
                    events.as_mut_ptr(),
                    self.max_events as i32,
                    self.timeout_ms,
                )
            };

            if n < 0 {
                return Err(Error::EpollWait(errno()));
            }
            if n == 0 {
                continue;
            }

            unsafe { events.set_len(n as usize) };

            for event in events.drain(..) {
                let fd = event.u64;
                if let Some(mut wakers) = self.wakers.get_mut(&fd) {
                    wakers.wake();
                }
            }
        }
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        // Wake all wakers to avoid leaking them.
        self.wakers
            .iter_mut()
            .for_each(|mut wakers| wakers.value_mut().wake());

        // Close the poll fd to avoid leaking it.
        unsafe { libc::close(self.poll_fd) };
    }
}
