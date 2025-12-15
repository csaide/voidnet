//! AF_XDP (eXpress Data Path) implementation.
//!
//! This module provides the core AF_XDP functionality including socket
//! abstraction, packet handling, and UMEM management.

pub mod context;
pub mod error;
pub mod program;
pub mod ring;
pub mod socket;
pub mod umem;
