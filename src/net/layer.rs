use crate::xdp::{error::NonBlocking, frame::FrameBuffer};

pub trait Layer<B: FrameBuffer> {
    fn process(&mut self, batch: B) -> NonBlocking<u32>;
}
