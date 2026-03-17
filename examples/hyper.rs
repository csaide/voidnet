#![deny(warnings)]

use std::convert::Infallible;
use std::net::SocketAddr;

use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use tokio::net::TcpListener;

use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::runtime::Builder;

// An async function that consumes a request, does nothing with it and returns a
// response.
async fn hello(_: Request<impl hyper::body::Body>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from("Hello World!"))))
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "[fc00:dead:cafe:1::1]:8080")]
    local_addr: SocketAddr,
    #[arg(short, long, default_value = "1")]
    num_threads: usize,
}

pub fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // This address is localhost
    let args = Args::parse();

    let rt = if args.num_threads > 1 {
        Builder::new_multi_thread()
            .enable_all()
            .worker_threads(args.num_threads.min(num_cpus::get()))
            .build()?
    } else {
        Builder::new_current_thread().enable_all().build()?
    };

    rt.block_on(async move {
        // Bind to the port and listen for incoming TCP connections
        let listener = TcpListener::bind(args.local_addr).await?;
        println!("Listening on http://{}", args.local_addr);
        loop {
            // When an incoming TCP connection is received grab a TCP stream for
            // client<->server communication.
            //
            // Note, this is a .await point, this loop will loop forever but is not a busy loop. The
            // .await point allows the Tokio runtime to pull the task off of the thread until the task
            // has work to do. In this case, a connection arrives on the port we are listening on and
            // the task is woken up, at which point the task is then put back on a thread, and is
            // driven forward by the runtime, eventually yielding a TCP stream.
            let (tcp, _) = listener.accept().await?;
            // Use an adapter to access something implementing `tokio::io` traits as if they implement
            // `hyper::rt` IO traits.
            let io = TokioIo::new(tcp);

            // Spin up a new task in Tokio so we can continue to listen for new TCP connection on the
            // current task without waiting for the processing of the HTTP1 connection we just received
            // to finish
            tokio::task::spawn(async move {
                // Handle the connection from the client using HTTP1 and pass any
                // HTTP requests received on that connection to the `hello` function
                if let Err(err) = http1::Builder::new()
                    .timer(TokioTimer::new())
                    .serve_connection(io, service_fn(hello))
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    })
}
