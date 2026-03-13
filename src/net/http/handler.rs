use crate::net::http::{HttpError, Request, ResponseWriter};

/// Trait for handling HTTP requests.
///
/// Implement this trait and pass it to `HttpListener::serve()` for the
/// high-level server API. Each connection spawns a task that calls
/// `handle()` for every request.
///
/// `Clone` is required because each spawned task gets its own copy.
pub trait HttpHandler: Clone + 'static {
    /// Handle an HTTP request and write the response.
    fn handle(
        &self,
        req: Request,
        res: ResponseWriter<'_>,
    ) -> impl std::future::Future<Output = Result<(), HttpError>> + '_;
}
