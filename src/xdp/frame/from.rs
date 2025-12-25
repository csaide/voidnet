use crate::xdp::frame::Frame;

pub trait FromFrame: Sized {
    fn from_frame(frame: Frame) -> Option<Self>;
}
