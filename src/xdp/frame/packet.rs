use crate::xdp::frame::Frame;

pub struct Packet {
    frames: Vec<Frame>,
}

impl Packet {
    #[inline(always)]
    pub fn new(mtu: u32, frame_size: usize) -> Self {
        let mut num_frames = (mtu / frame_size as u32) as usize;
        if mtu % frame_size as u32 != 0 {
            num_frames += 1;
        }

        Self {
            frames: Vec::with_capacity(num_frames),
        }
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.frames.capacity()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    #[inline(always)]
    pub fn push_frame(&mut self, frame: Frame) {
        self.frames.push(frame);
    }

    #[inline(always)]
    pub fn to_frames(self) -> Vec<Frame> {
        self.frames
    }
}
