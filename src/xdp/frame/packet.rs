use crate::xdp::frame::Frame;

pub struct Packet<const S: usize = 16> {
    frames: [Option<Frame>; S],
    len: usize,
}

impl<const S: usize> Packet<S> {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            frames: [const { None }; S],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        S
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn push_frame(&mut self, frame: Frame) {
        self.frames[self.len] = Some(frame);
        self.len += 1;
    }

    #[inline(always)]
    pub fn pop_frame(&mut self) -> Option<Frame> {
        if self.len == 0 {
            return None;
        }
        let len = self.len;
        self.len -= 1;
        self.frames[len - 1].take()
    }
}

impl<const S: usize> Default for Packet<S> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
