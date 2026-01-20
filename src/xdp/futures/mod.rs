//! Futures for AF_XDP.
//!
//! This module provides futures for the [Tokio] (feature: `tokio`), [Smol] (feature: `smol`), and [Local] (feature: `local`) runtimes, and associated types for working with the XDP subsystem.
//!
//! [Tokio]: tokio
//! [Smol]: smol
//! [Local]: local

macro_rules! cfg_block {
    (#[$meta:meta] { $($item:item)* }) => {
        $(
            #[$meta]
            $item
        )*
    };
}

cfg_block! {
    #[cfg(feature = "tokio")]
    {
        mod tokio;

        pub use tokio::{TokioCompFuture, TokioCompletionQueue};
        pub use tokio::{TokioFillFuture, TokioFillQueue};
        pub use tokio::{TokioRecvFuture, TokioSocketRx};
        pub use tokio::{TokioSendFuture, TokioSocketTx};
        pub use tokio::TokioSocket;
        pub use tokio::TokioUmem;
        pub use tokio::TokioFdFactory;
    }
}

cfg_block! {
    #[cfg(feature = "smol")]
    {
        mod smol;

        pub use smol::{SmolFd, SmolFdFactory};
        pub use smol::{SmolCompFuture, SmolCompletionQueue};
        pub use smol::{SmolFillFuture, SmolFillQueue};
        pub use smol::{SmolRecvFuture, SmolSocketRx};
        pub use smol::{SmolSendFuture, SmolSocketTx};
        pub use smol::SmolSocket;
        pub use smol::SmolUmem;
    }
}

cfg_block! {
    #[cfg(feature = "local")]
    {
        mod local;
        pub use local::{LocalCompFuture, LocalCompletionQueue};
        pub use local::{LocalFillFuture, LocalFillQueue};
        pub use local::{LocalRecvFuture, LocalSocketRx};
        pub use local::{LocalSendFuture, LocalSocketTx};
        pub use local::LocalSocket;
        pub use local::LocalUmem;
        pub use local::LocalExecutor;
    }
}
