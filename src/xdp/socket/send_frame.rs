use std::ops::{Deref, DerefMut};

use crate::xdp::umem::Frame;

#[derive(Debug)]
pub enum FinalizedFrame {
    Committed(Frame),
    Aborted(Frame),
}

pub struct SendFrame {
    frame: Frame,
}

impl SendFrame {
    pub(super) fn new(frame: Frame) -> Self {
        Self { frame }
    }

    pub fn commit(self) -> FinalizedFrame {
        FinalizedFrame::Committed(self.frame)
    }

    pub fn abort(self) -> FinalizedFrame {
        FinalizedFrame::Aborted(self.frame)
    }
}

impl Deref for SendFrame {
    type Target = Frame;

    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

impl DerefMut for SendFrame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.frame
    }
}
