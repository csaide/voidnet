use std::{ptr::null_mut, sync::Arc, task::Waker};

use dashmap::{DashMap, Entry};
use errno::errno;
use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN, EPOLLOUT, epoll_create1,
    epoll_ctl, epoll_event, epoll_wait,
};

use super::error::{Error, Result};

static POLLER: std::sync::OnceLock<Arc<Poller>> = std::sync::OnceLock::new();

pub(crate) fn get_poller() -> &'static Arc<Poller> {
    POLLER.get_or_init(|| {
        let poller = Arc::new(Poller::new(1024, 100).unwrap());
        std::thread::spawn({
            let poller = poller.clone();
            move || match poller.poll() {
                Ok(_) => (),
                Err(e) => eprintln!("Poller error: {}", e),
            }
        });
        poller
    })
}

pub struct Poller {
    poll_fd: i32,
    timeout_ms: i32,
    max_events: usize,
    wakers: DashMap<u64, Waker>,
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
            wakers: DashMap::new(),
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
                entry.get_mut().clone_from(&waker);
            }
            Entry::Vacant(entry) => {
                self.register_socket(fd)?;
                entry.insert(waker.clone());
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
                if let Some((_, waker)) = self.wakers.remove(&event.u64) {
                    self.deregister_socket(event.u64 as i32)?;
                    waker.wake();
                }
            }
        }
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        unsafe { libc::close(self.poll_fd) };
    }
}
