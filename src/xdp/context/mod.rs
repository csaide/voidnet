//! XDP context management for AF_XDP socket coordination.
//!
//! [`XdpContext`] is the entrypoint for working with XDP. It loads and attaches
//! an XDP BPF program to a network interface, then coordinates socket registration
//! so the kernel can route packets to userspace.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                       User Space                            │
//! │  ┌─────────────┐    ┌─────────┐    ┌───────────────────┐    │
//! │  │ XdpContext  │───▶│  Umem   │───▶│ Socket (AF_XDP)   │    │
//! │  │             │    │         │    │                   │    │
//! │  │ • BPF Prog  │    │ • Frames│    │ • RX Ring         │    │
//! │  │ • xsks_map  │    │ • FQ/CQ │    │ • TX Ring         │    │
//! │  │ • .bss map  │    │         │    │                   │    │
//! │  └─────────────┘    └─────────┘    └───────────────────┘    │
//! │         │                                   ▲               │
//! └─────────┼───────────────────────────────────┼───────────────┘
//!           │ BPF Maps                          │ Shared Memory
//! ┌─────────▼───────────────────────────────────┼───────────────┐
//! │                      Kernel                 │               │
//! │  ┌─────────────┐                   ┌────────┴─────────┐     │
//! │  │  XDP Prog   │──────────────────▶│   AF_XDP Socket  │     │
//! │  │             │   XDP_REDIRECT    │                  │     │
//! │  └─────────────┘                   └──────────────────┘     │
//! │         ▲                                                   │
//! │         │                                                   │
//! │  ┌──────┴──────┐                                            │
//! │  │   NIC/DRV   │◀──── Incoming Packets                      │
//! │  └─────────────┘                                            │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```no_run
//! use libvoid::xdp::{
//!     context::XdpContext,
//!     program::AttachMode,
//!     umem::Umem,
//!     socket::Socket,
//! };
//!
//! // 1. Attach XDP program to the interface
//! let mut ctx = XdpContext::builder("eth0")
//!     .attach_mode(AttachMode::default())
//!     .enable_fragmentation(false)
//!     .build()?;
//!
//! // 2. Create shared memory
//! let mut umem = Umem::builder(&mut ctx).num_frames(4096).build()?;
//!
//! // 3. Create an AF_XDP socket
//! let socket = Socket::builder(&mut ctx, "eth0", 0).build(umem.owner().clone())?;
//!
//! // 4. Process packets via RX/TX rings...
//! # Ok::<(), libvoid::xdp::error::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! `XdpContext` is `Send` but not `Sync`. You should have one context per interface.
//! Create all sockets on a single thread, then distribute them to workers.
//!
//! # Cleanup
//!
//! The XDP program is detached when [`XdpContext`] is dropped. Handle signals
//! (SIGINT, SIGTERM) to ensure graceful shutdown.

mod ctx;

pub use ctx::XdpContext;
