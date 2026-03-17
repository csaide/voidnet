use std::{
    ffi::CString,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
};

use coarsetime::Duration;

use crate::{
    net::NeighborUpdate,
    netlink,
    rt::{affinity::pin_core, local::LocalRuntime},
    xdp::{
        context::XdpContext,
        error::{Error, Result},
        program::AttachMode,
        socket::{CopyMode, Socket},
        umem::{Umem, UmemBuilder},
    },
};

const DEFAULT_ARP_TTL: Duration = Duration::from_secs(60);

/// Determines which queues to bind.
enum QueueSelection {
    /// Auto-discover all queues via ethtool.
    Auto,
    /// Bind exactly these queue IDs.
    Explicit(Vec<u32>),
    /// Auto-discover, but cap at this many (starting from queue 0).
    Max(u32),
}

/// Builder for configuring and constructing a multi-threaded [`Runtime`].
///
/// Mirrors the configuration surface of `LocalRuntimeBuilder` with additional
/// queue selection options. All threads receive identical configuration.
pub struct RuntimeBuilder<'name> {
    if_name: &'name str,
    queue_selection: QueueSelection,
    attach_mode: AttachMode,
    umem_builder: UmemBuilder,
    rx_ring_size: u32,
    tx_ring_size: u32,
    busy_poll: bool,
    busy_poll_batch_size: usize,
    busy_poll_timeout_us: i32,
    copy_mode: CopyMode,
    enable_fragmentation: bool,
    arp_ttl: Duration,
}

impl<'name> RuntimeBuilder<'name> {
    /// Creates a new [`RuntimeBuilder`] for the given interface name.
    pub fn new(if_name: &'name str) -> Self {
        Self {
            if_name,
            queue_selection: QueueSelection::Auto,
            attach_mode: AttachMode::default(),
            umem_builder: UmemBuilder::new(),
            rx_ring_size: 0, // 0 means use SocketBuilder defaults
            tx_ring_size: 0,
            busy_poll: false,
            busy_poll_batch_size: 32,
            busy_poll_timeout_us: 20,
            copy_mode: CopyMode::default(),
            enable_fragmentation: false,
            arp_ttl: DEFAULT_ARP_TTL,
        }
    }

    /// Explicitly select which queue IDs to bind.
    /// Mutually exclusive with `max_queues`.
    pub fn queues(mut self, queues: &[u32]) -> Self {
        self.queue_selection = QueueSelection::Explicit(queues.to_vec());
        self
    }

    /// Auto-discover queues but cap at this count.
    /// Mutually exclusive with `queues`.
    pub fn max_queues(mut self, max: u32) -> Self {
        self.queue_selection = QueueSelection::Max(max);
        self
    }

    /// Sets the attach mode for the XDP program.
    pub fn attach_mode(mut self, mode: AttachMode) -> Self {
        self.attach_mode = mode;
        self
    }

    /// Enables or disables fragmentation support.
    pub fn enable_fragmentation(mut self, enable: bool) -> Self {
        self.enable_fragmentation = enable;
        self
    }

    /// Sets the ARP TTL for neighbor entries.
    pub fn arp_ttl(mut self, ttl: Duration) -> Self {
        self.arp_ttl = ttl;
        self
    }

    /// Sets the completion ring size for each UMEM.
    pub fn completion_ring_size(mut self, size: u32) -> Self {
        self.umem_builder = self.umem_builder.completion_ring_size(size);
        self
    }

    /// Sets the fill ring size for each UMEM.
    pub fn fill_ring_size(mut self, size: u32) -> Self {
        self.umem_builder = self.umem_builder.fill_ring_size(size);
        self
    }

    /// Sets the frame size for each UMEM.
    pub fn frame_size(mut self, size: usize) -> Self {
        self.umem_builder = self.umem_builder.frame_size(size);
        self
    }

    /// Enables or disables busy polling.
    pub fn busy_poll(mut self, enable: bool) -> Self {
        self.busy_poll = enable;
        self
    }

    /// Sets the busy poll batch size.
    pub fn busy_poll_batch_size(mut self, size: usize) -> Self {
        self.busy_poll_batch_size = size;
        self
    }

    /// Sets the busy poll timeout in microseconds.
    pub fn busy_poll_timeout_us(mut self, timeout: i32) -> Self {
        self.busy_poll_timeout_us = timeout;
        self
    }

    /// Enables or disables huge tables for UMEM allocation.
    pub fn huge_tables(mut self, enable: bool) -> Self {
        self.umem_builder = self.umem_builder.huge_tables(enable);
        self
    }

    /// Enables or disables unaligned frame mode.
    pub fn unaligned(mut self, enable: bool) -> Self {
        self.umem_builder = self.umem_builder.unaligned(enable);
        self
    }

    /// Sets the RX ring size for each socket.
    pub fn rx_ring_size(mut self, size: u32) -> Self {
        self.rx_ring_size = size;
        self
    }

    /// Sets the TX ring size for each socket.
    pub fn tx_ring_size(mut self, size: u32) -> Self {
        self.tx_ring_size = size;
        self
    }

    /// Sets the copy mode for each socket.
    pub fn copy_mode(mut self, mode: CopyMode) -> Self {
        self.copy_mode = mode;
        self
    }

    /// Resolve interface name to index using libc::if_nametoindex.
    fn resolve_if_index(if_name: &str) -> Result<i32> {
        let c_name = CString::new(if_name).map_err(Error::InterfaceNameToIndex)?;
        let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
        if index == 0 {
            return Err(Error::InterfaceNotFound);
        }
        Ok(index as i32)
    }

    /// Resolve which queue IDs to bind based on the queue selection strategy.
    fn resolve_queues(&self) -> Result<Vec<u32>> {
        match &self.queue_selection {
            QueueSelection::Explicit(queues) => Ok(queues.clone()),
            QueueSelection::Auto => {
                let if_index = Self::resolve_if_index(self.if_name)?;
                let count = netlink::get_queue_count(if_index)?;
                Ok((0..count).collect())
            }
            QueueSelection::Max(max) => {
                let if_index = Self::resolve_if_index(self.if_name)?;
                let count = netlink::get_queue_count(if_index)?;
                let capped = count.min(*max);
                Ok((0..capped).collect())
            }
        }
    }

    /// Build the multi-threaded Runtime.
    pub fn build(self) -> Result<Runtime> {
        let queues = self.resolve_queues()?;

        // Validate all queue IDs are within xsks_map bounds.
        for &qid in &queues {
            if qid >= 2048 {
                return Err(Error::QueueIdOutOfRange(qid));
            }
        }

        Ok(Runtime {
            if_name: self.if_name.to_string(),
            queues,
            umem_builder: self.umem_builder,
            rx_ring_size: self.rx_ring_size,
            tx_ring_size: self.tx_ring_size,
            busy_poll: self.busy_poll,
            busy_poll_batch_size: self.busy_poll_batch_size,
            busy_poll_timeout_us: self.busy_poll_timeout_us,
            copy_mode: self.copy_mode,
            enable_fragmentation: self.enable_fragmentation,
            arp_ttl: self.arp_ttl,
            attach_mode: self.attach_mode,
        })
    }
}

/// Multi-threaded runtime that spawns one worker thread per hardware queue.
///
/// Created via `Runtime::builder("eth0").build()`. The `run` method drives
/// the two-phase lifecycle: setup on the main thread, then spawn workers.
pub struct Runtime {
    if_name: String,
    queues: Vec<u32>,
    umem_builder: UmemBuilder,
    rx_ring_size: u32,
    tx_ring_size: u32,
    busy_poll: bool,
    busy_poll_batch_size: usize,
    busy_poll_timeout_us: i32,
    copy_mode: CopyMode,
    enable_fragmentation: bool,
    arp_ttl: Duration,
    attach_mode: AttachMode,
}

impl Runtime {
    /// Returns a builder for constructing a multi-threaded Runtime.
    pub fn builder<'name>(if_name: &'name str) -> RuntimeBuilder<'name> {
        RuntimeBuilder::new(if_name)
    }

    /// Run the multi-threaded event loop.
    ///
    /// Phase 1 (main thread): Create XdpContext, UMEMs, sockets; register all sockets.
    /// Phase 2 (worker threads): Spawn one thread per queue, each running a LocalRuntime.
    ///
    /// The factory closure is called on each worker thread with the queue ID.
    /// Returns when all threads exit, or on the first error (which triggers shutdown).
    pub fn run<F, Fut>(&self, exit: Arc<AtomicBool>, factory: F) -> Result<()>
    where
        F: Fn(u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        // ---- Phase 1: Setup (main thread) ----
        let mut ctx = XdpContext::builder(&self.if_name)
            .attach_mode(self.attach_mode)
            .enable_fragmentation(self.enable_fragmentation)
            .build()?;

        let info = ctx.info();
        let mtu = info.mtu;
        let rx_offload = info.rx_offload;
        let tx_offload = info.tx_offload;

        // Create per-queue resources.
        let mut workers: Vec<(u32, Umem<'static>, Socket<'static>)> = Vec::new();

        for &queue_id in &self.queues {
            let umem: Umem<'static> = self.umem_builder.clone().build()?;

            let mut socket_builder = Socket::builder(&self.if_name, queue_id);
            if self.rx_ring_size > 0 {
                socket_builder = socket_builder.rx_ring_size(self.rx_ring_size);
            }
            if self.tx_ring_size > 0 {
                socket_builder = socket_builder.tx_ring_size(self.tx_ring_size);
            }
            socket_builder = socket_builder
                .busy_poll(self.busy_poll)
                .busy_poll_batch_size(self.busy_poll_batch_size)
                .busy_poll_timeout_us(self.busy_poll_timeout_us)
                .copy_mode(self.copy_mode)
                .enable_fragmentation(self.enable_fragmentation);

            let socket = socket_builder.build(&mut ctx, umem.owner().clone())?;

            workers.push((queue_id, umem, socket));
        }

        // ---- Build neighbor broadcast channel mesh ----
        let num_queues = workers.len();
        let mut channels: Vec<(Vec<SyncSender<NeighborUpdate>>, Receiver<NeighborUpdate>)> =
            Vec::with_capacity(num_queues);

        if num_queues > 1 {
            let mut receivers: Vec<Receiver<NeighborUpdate>> = Vec::with_capacity(num_queues);
            let mut all_senders: Vec<SyncSender<NeighborUpdate>> = Vec::with_capacity(num_queues);
            for _ in 0..num_queues {
                let (tx, rx) = mpsc::sync_channel(256);
                all_senders.push(tx);
                receivers.push(rx);
            }

            // For each queue i, collect senders to all queues j != i.
            let mut senders: Vec<Vec<SyncSender<NeighborUpdate>>> = Vec::with_capacity(num_queues);
            for i in 0..num_queues {
                let mut queue_senders = Vec::with_capacity(num_queues - 1);
                for (j, sender) in all_senders.iter().enumerate() {
                    if i != j {
                        queue_senders.push(sender.clone());
                    }
                }
                senders.push(queue_senders);
            }

            for (tx_vec, rx) in senders.into_iter().zip(receivers.into_iter()) {
                channels.push((tx_vec, rx));
            }
        } else {
            // Single queue via Runtime — no broadcast needed.
            let (_, rx) = mpsc::sync_channel(1);
            channels.push((Vec::new(), rx));
        }

        // ---- Phase 2: Run (worker threads) ----
        let factory = Arc::new(factory);
        let mut handles = Vec::new();

        for ((queue_id, umem, socket), (neighbor_tx, neighbor_rx)) in
            workers.into_iter().zip(channels.into_iter())
        {
            let exit = exit.clone();
            let factory = factory.clone();
            let if_name = self.if_name.clone();
            let arp_ttl = self.arp_ttl;

            let handle = std::thread::Builder::new()
                .name(format!("voidnet-q{queue_id}"))
                .spawn(move || -> Result<()> {
                    pin_core(queue_id);

                    println!("spawning worker thread for queue {queue_id}");
                    let mut rt = LocalRuntime::new_worker(
                        &if_name,
                        umem,
                        socket,
                        mtu,
                        rx_offload,
                        tx_offload,
                        arp_ttl,
                        neighbor_tx,
                        neighbor_rx,
                    )?;

                    let result = rt.run(exit.clone(), factory(queue_id));

                    // First-failure propagation: signal all other threads to exit.
                    if result.is_err() {
                        exit.store(true, Ordering::Relaxed);
                    }

                    result
                })
                .map_err(|e| Error::Other(format!("failed to spawn thread: {e}")))?;

            handles.push(handle);
        }

        // ---- Phase 3: Join ----
        // Keep ctx alive (holds BPF program) until all workers are done.
        let _ctx = ctx;

        let mut first_error: Option<Error> = None;

        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
                Err(panic_payload) => {
                    if first_error.is_none() {
                        let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                            format!("worker thread panicked: {s}")
                        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                            format!("worker thread panicked: {s}")
                        } else {
                            "worker thread panicked".to_string()
                        };
                        first_error = Some(Error::Other(msg));
                    }
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::test_utils::TestVethPair;

    /// Test that Runtime can be constructed and run with a single queue on a veth pair.
    #[test]
    fn runtime_single_queue_veth() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let exit = Arc::new(AtomicBool::new(false));
        let exit_clone = exit.clone();

        // Signal exit after a brief moment so the test doesn't run forever.
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            exit_clone.store(true, Ordering::Relaxed);
        });

        let rt = Runtime::builder(veth.outer_name())
            .queues(&[0])
            .build()
            .expect("failed to build runtime");

        let result = rt.run(exit, |_queue_id| async {
            // No-op: just confirm the event loop runs and exits cleanly.
        });

        assert!(
            result.is_ok(),
            "runtime should exit cleanly: {:?}",
            result.err()
        );
    }

    /// Test that explicit queue selection works at build time.
    #[test]
    fn runtime_builder_explicit_queues() {
        let veth = TestVethPair::new().expect("failed to create veth pair");

        let rt = Runtime::builder(veth.outer_name()).queues(&[0]).build();

        assert!(rt.is_ok(), "should build with explicit queue 0");
    }

    /// Test that queue ID validation rejects out-of-range values.
    #[test]
    fn runtime_builder_rejects_out_of_range_queue() {
        let result = Runtime::builder("lo").queues(&[3000]).build();

        assert!(result.is_err(), "should reject queue ID >= 2048");
    }
}
