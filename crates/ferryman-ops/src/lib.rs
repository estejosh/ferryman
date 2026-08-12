//! The things Ferryman *does*, separated from the program that types them.
//!
//! Enabling a project and running the worker and reviewer loops used to live inside the
//! `ferry` binary. That meant anything other than the CLI - a tray application, a
//! service wrapper, an embedding - could only reach them by spawning a process and
//! parsing output written for a person to read. This crate exists so there is exactly
//! one implementation and every caller uses it.
//!
//! # Callers decide what the user sees
//!
//! Nothing in here prints. Progress is reported through [`Progress`], which the CLI
//! implements by writing to stdout and a background service implements by logging or
//! ignoring. A library that prints has decided that its caller is a terminal, and that
//! decision is what made this code impossible to reuse in the first place.

#![forbid(unsafe_code)]

pub mod agent;
pub mod enable;
pub mod identity;

/// Where a long-running operation reports what it is doing.
///
/// Deliberately tiny. The temptation is a structured event enum with a variant per
/// occurrence, which then has to change every time a message does; a line of text and a
/// severity covers what a caller actually needs to decide whether to show it.
pub trait Progress {
    /// Something happened worth telling the operator about.
    fn info(&self, message: &str);
    /// Something failed but the loop is continuing.
    fn warn(&self, message: &str);
}

/// Reports nothing. For callers that only want the return value.
pub struct Silent;

impl Progress for Silent {
    fn info(&self, _message: &str) {}
    fn warn(&self, _message: &str) {}
}

/// Writes to stdout and stderr, the way a command-line program should.
pub struct Stdout;

impl Progress for Stdout {
    fn info(&self, message: &str) {
        println!("{message}");
    }
    fn warn(&self, message: &str) {
        eprintln!("{message}");
    }
}
