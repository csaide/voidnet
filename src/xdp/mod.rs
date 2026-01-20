//! AF_XDP bindings for the VoidNet project.
//!
//! This module provides a safe API for working with AF_XDP, including creating and managing XDP programs, sockets, and umem.
//!
//! This also includes a full set of async runtime integrations:
//! - [Tokio](https://tokio.rs/) (requires the `tokio` feature)
//! - [Smol](https://docs.rs/smol/latest/smol/) (requires the `smol` feature)
//!
//! As well as purpose built Local runtime integration (requires the `local` feature).

pub mod context;
pub mod error;
mod flags;
pub mod frame;
#[cfg(any(feature = "tokio", feature = "smol", feature = "local"))]
pub mod futures;
pub mod program;
pub mod ring;
pub mod socket;
pub mod test_utils;
pub mod umem;
