crate::cfg_block! {
    #[cfg(feature = "tokio")]
    {
        mod tokio;

        pub use tokio::{TokioCompFuture, TokioCompletionQueue};
        pub use tokio::{TokioFillFuture, TokioFillQueue};
        pub use tokio::{TokioRecvFuture, TokioSocketRx};
        pub use tokio::{TokioSendFuture, TokioSocketTx};
        pub use tokio::TokioSocket;
    }
}
