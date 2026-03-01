use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crossbeam_utils::Backoff;

use crate::xdp::{
    error::Result,
    frame::{BasicFrameBuffer, Frame, FrameBuffer},
    socket::Socket,
    umem::Umem,
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IoResult {
    #[default]
    Reclaim,
    Transmit,
}

pub fn run_rt_thread<'umem, F>(
    exit: Arc<AtomicBool>,
    mut socket: Socket<'umem>,
    mut umem: Umem<'umem>,
    mut f: F,
) -> Result<()>
where
    F: FnMut(&mut Frame<'umem>) -> IoResult,
{
    let mut incoming = umem.init_buffer::<BasicFrameBuffer>().unwrap();
    let mut rx_return = BasicFrameBuffer::new(incoming.num_frames());
    let mut tx_return = BasicFrameBuffer::new(incoming.num_frames());

    umem.maybe_wake_fill_queue(socket.fd())?;
    umem.process_fill_queue(&mut incoming)
        .expect("failed to process fill queue");

    let backoff = Backoff::new();
    while !exit.load(Ordering::Relaxed) {
        match socket.recv(&mut incoming) {
            Ok(_) => {
                backoff.reset();
            }
            Err(_) => {
                backoff.snooze();
                continue;
            }
        }

        for mut frame in incoming.take_frames() {
            match f(&mut frame) {
                IoResult::Reclaim => {
                    rx_return.push(frame);
                }
                IoResult::Transmit => {
                    tx_return.push(frame);
                }
            }
        }

        if tx_return.num_frames() > 0 {
            while let Err(_) = socket.send(&mut tx_return) {
                socket.maybe_wake()?;
            }

            while let Err(_) = umem.process_completion_queue(&mut rx_return) {
                socket.maybe_wake()?;
            }
        }

        umem.maybe_wake_fill_queue(socket.fd())?;
        umem.process_fill_queue(&mut rx_return)
            .expect("failed to process fill queue");
    }
    Ok(())
}
