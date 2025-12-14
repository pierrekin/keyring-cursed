//! # keyring-cursed
//!
//! A wrapper over [`keyring`] that allows storing secrets larger than the
//! platform's per-entry limit by automatically splitting them across multiple entries.
//!
//! ## Usage
//!
//! ```no_run
//! use keyring_cursed::{Entry, Result};
//!
//! fn main() -> Result<()> {
//!     let entry = Entry::new("my-service", "my-user")?;
//!
//!     // Store a secret (automatically splits if too large)
//!     entry.set_password("my-secret-password")?;
//!
//!     // Retrieve it (automatically reassembles)
//!     let password = entry.get_password()?;
//!
//!     // Clean up
//!     entry.delete_credential()?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Storage Format
//!
//! Secrets are stored with a naming convention of `{user}.{part}` where part is
//! 1-indexed. Each part contains a header `{part}/{total}|` followed by the payload.
//!
//! For example, a secret split into 3 parts for user "alice":
//! - `alice.1` → `1/3|<chunk1>`
//! - `alice.2` → `2/3|<chunk2>`
//! - `alice.3` → `3/3|<chunk3>`

mod chunk;
mod entry;
mod format;

pub use entry::Entry;

use thiserror::Error;

/// Errors that can occur when working with the credential store.
#[derive(Debug, Error)]
pub enum Error {
    /// The underlying keyring operation failed.
    #[error("keyring error: {0}")]
    Keyring(#[from] keyring::Error),

    /// The stored secret has invalid or corrupted format.
    #[error("corrupted secret: {0}")]
    CorruptedSecret(String),

    /// The retrieved data is not valid UTF-8 (when using get_password).
    #[error("secret is not valid UTF-8")]
    BadEncoding,

    /// Invalid argument provided.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

/// A Result type alias using our Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Returns the maximum payload size per chunk for the current platform.
///
/// This can be useful for estimating how many parts a secret will be split into.
pub fn max_chunk_size() -> usize {
    chunk::max_chunk_size()
}
