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
    }
}

cfg_block! {
    #[cfg(feature = "smol")]
    {
        mod smol;
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
