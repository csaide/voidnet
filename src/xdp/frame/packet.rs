use std::{cmp::min, collections::vec_deque::IterMut};

use crate::xdp::frame::LocalFrameBuffer;

use super::Frame;

pub struct PacketWriter<'a> {
    frames: IterMut<'a, Frame>,
    frame_size: usize,
}

impl<'a> PacketWriter<'a> {
    pub fn new(frames: &'a mut LocalFrameBuffer, frame_size: usize) -> Self {
        Self {
            frames: frames.iter_mut(),
            frame_size,
        }
    }

    pub unsafe fn copy_from<I: AsRef<[u8]>>(&mut self, incoming: I) -> Option<()> {
        let incoming = incoming.as_ref();

        if self.frames.len() * self.frame_size < incoming.len() {
            return None;
        }

        let mut start = 0;
        while start < incoming.len() {
            let frame = self.frames.next().unwrap();
            let end = start + min(self.frame_size, incoming.len() - start);

            unsafe {
                frame.copy_from(&incoming[start..end]);
                frame.set_fragment(end != incoming.len());
            }

            start = end;
        }

        Some(())
    }
}
