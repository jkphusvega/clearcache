//! UI-independent logic shared by the Tauri commands and the `scan` example CLI.
//! Nothing here knows about Tauri; progress and accounting results leave through traits/callbacks.

pub mod accounting;
pub mod paths;
pub mod protect;
pub mod rules;
pub mod scan;
pub mod session;
pub mod targets;

#[cfg(test)]
mod audit_tests;
#[cfg(test)]
pub(crate) mod testzone;
