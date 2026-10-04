//! MLSChat delivery service.
//!
//! MLS needs a delivery service that hands every member the same sequence of
//! commits (RFC 9750 section 5). This one keeps a totally ordered log per group
//! in RocksDB and accepts a commit only if it was built on the group's current
//! epoch, so two members committing at once cannot split the group.

pub mod server;
pub mod store;
mod web;
pub use wire;

pub use server::{Config, Mode, Server};
