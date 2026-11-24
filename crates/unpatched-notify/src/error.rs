//! Errors. Messages say what to do next and never contain secrets.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A channel is enabled but its secret is missing.
    #[error(
        "{var} is not set, but {what} is enabled. Set {var} (a repository secret in GitHub Actions) or turn {what} off in unpatched.yml."
    )]
    MissingEnv {
        var: &'static str,
        what: &'static str,
    },
    #[error("{0}")]
    Config(String),
    /// The request did not complete (DNS, TLS, timeout, ...).
    #[error("{service}: request failed: {message}")]
    Http { service: String, message: String },
    /// The service answered with an error status.
    #[error("{service}: HTTP {status}: {message}")]
    Api {
        service: String,
        status: u16,
        message: String,
    },
    #[error("state: {0}")]
    State(String),
    /// Some channels failed; the others were still delivered.
    #[error("{} delivery problem(s): {}", .errors.len(), .errors.join("; "))]
    Delivery { errors: Vec<String> },
}

pub type Result<T> = std::result::Result<T, Error>;
