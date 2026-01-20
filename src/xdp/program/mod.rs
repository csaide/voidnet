//! XDP program management for AF_XDP.
//!
//! This module provides a safe API for managing XDP programs, including creating and attaching them to network interfaces.

mod info;
mod map;
mod mode;
mod prog;

pub use info::XdpInfo;
pub use map::Map;
pub use mode::AttachMode;
pub use prog::XdpProgram;
