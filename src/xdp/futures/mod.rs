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
