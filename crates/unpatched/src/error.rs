//! Errors the command line shows, and the exit code each one means.

use miette::{Diagnostic, Report};

pub const EXIT_FIX_TODAY: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_DATA: u8 = 3;
pub const EXIT_DELIVERY: u8 = 4;

/// What went wrong, and what to do about it.
#[derive(Debug, thiserror::Error, Diagnostic)]
#[error("{message}")]
pub struct Problem {
    message: String,
    #[help]
    help: Option<String>,
}

/// A failed command: the exit code and what to tell the person.
#[derive(Debug)]
pub struct Failure {
    pub code: u8,
    pub report: Report,
}

pub type Res<T> = Result<T, Failure>;

impl Failure {
    fn new(code: u8, message: impl Into<String>, help: Option<String>) -> Self {
        Self {
            code,
            report: Report::new(Problem {
                message: message.into(),
                help,
            }),
        }
    }

    /// A usage or configuration problem (exit 2).
    pub fn usage(message: impl Into<String>, help: impl Into<String>) -> Self {
        Self::new(EXIT_USAGE, message, Some(help.into()))
    }

    /// A data problem: no database, too old, a download failed (exit 3).
    pub fn data(message: impl Into<String>, help: impl Into<String>) -> Self {
        Self::new(EXIT_DATA, message, Some(help.into()))
    }

    /// A delivery problem (exit 4).
    pub fn delivery(message: impl Into<String>, help: impl Into<String>) -> Self {
        Self::new(EXIT_DELIVERY, message, Some(help.into()))
    }

    /// Wrap a diagnostic that already has its own source code and labels.
    pub fn with_report(code: u8, report: Report) -> Self {
        Self { code, report }
    }
}
