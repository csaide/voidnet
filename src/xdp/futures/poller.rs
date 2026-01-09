use std::{
    mem::MaybeUninit,
    ptr::null_mut,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Waker,
};

use dashmap::{DashMap, Entry};
use errno::errno;
use libc::{
    EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN, EPOLLOUT, epoll_create1,
    epoll_ctl, epoll_event, epoll_wait,
};
use smallvec::{SmallVec, smallvec};

use crate::xdp::error::{Error, Result};

const MAX_EVENTS: usize = 1024;

#[derive(Default)]
enum WakerSlot {
    #[default]
    Empty,
    Single(Waker),
    Multi(SmallVec<[Waker; 4]>),
}

impl WakerSlot {
    pub fn new(waker: Waker) -> Self {
        Self::Single(waker)
    }

    pub fn append(&mut self, waker: Waker) {
        match std::mem::take(self) {
            Self::Empty => *self = Self::Single(waker),
            Self::Single(current) => {
                if waker.will_wake(&current) {
                    *self = Self::Single(current);
                } else {
                    *self = Self::Multi(smallvec![current, waker]);
                }
            }
            Self::Multi(mut wakers) => {
                if wakers.iter().any(|waker| waker.will_wake(&waker)) {
                    *self = Self::Multi(wakers);
                } else {
                    wakers.push(waker);
                    *self = Self::Multi(wakers);
                }
            }
        }
    }

    pub fn wake(&mut self) {
        match std::mem::take(self) {
            Self::Empty => (),
            Self::Single(waker) => waker.wake(),
            Self::Multi(mut wakers) => wakers.drain(..).for_each(|waker| waker.wake()),
        }
    }
}

pub(crate) struct Poller {
    poll_fd: i32,
    exit: Arc<AtomicBool>,
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
            exit: Arc::new(AtomicBool::new(false)),
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

    pub fn exit(&self) {
        self.exit.store(true, Ordering::Relaxed);
    }

    pub fn poll(&self) -> Result<()> {
        let mut events = [MaybeUninit::<epoll_event>::uninit(); MAX_EVENTS];
        while !self.exit.load(Ordering::Relaxed) {
            let n = unsafe {
                epoll_wait(
                    self.poll_fd,
                    events.as_mut_ptr() as *mut epoll_event,
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

            for i in 0..n {
                let event: &epoll_event = unsafe { events[i as usize].assume_init_ref() };
                let fd = event.u64;
                if let Some(mut wakers) = self.wakers.get_mut(&fd) {
                    wakers.wake();
                }
            }
        }
        Ok(())
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
