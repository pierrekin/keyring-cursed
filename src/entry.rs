use crate::chunk::{chunks_needed, max_chunk_size};
use crate::format::{decode_part, encode_part};
use crate::{Error, Result};

/// An entry in the credential store that can hold secrets of any size.
///
/// Large secrets are automatically split across multiple underlying keyring entries.
/// Small secrets use a single entry with minimal overhead.
#[derive(Debug, Clone)]
pub struct Entry {
    service: String,
    user: String,
}

impl Entry {
    /// Create a new entry for the given service and user.
    pub fn new(service: &str, user: &str) -> Result<Self> {
        if service.is_empty() {
            return Err(Error::InvalidArgument("service cannot be empty".into()));
        }
        if user.is_empty() {
            return Err(Error::InvalidArgument("user cannot be empty".into()));
        }
        Ok(Self {
            service: service.to_string(),
            user: user.to_string(),
        })
    }

    /// Store a password (UTF-8 string) in the credential store.
    pub fn set_password(&self, password: &str) -> Result<()> {
        self.set_secret(password.as_bytes())
    }

    /// Retrieve a password (UTF-8 string) from the credential store.
    pub fn get_password(&self) -> Result<String> {
        let secret = self.get_secret()?;
        String::from_utf8(secret).map_err(|_| Error::BadEncoding)
    }

    /// Store binary data in the credential store.
    ///
    /// The data is automatically split across multiple entries if it exceeds
    /// the platform's per-entry limit.
    pub fn set_secret(&self, secret: &[u8]) -> Result<()> {
        // First, clean up any existing parts
        self.delete_credential()?;

        let chunk_size = max_chunk_size();
        let total = chunks_needed(secret.len());

        // Write parts in reverse order (N down to 1)
        // This ensures part 1 acts as a "commit" marker
        for part in (1..=total).rev() {
            let start = (part - 1) * chunk_size;
            let end = std::cmp::min(part * chunk_size, secret.len());
            let chunk_data = &secret[start..end];

            let encoded = encode_part(part, total, chunk_data);
            let entry = self.part_entry(part)?;
            entry.set_secret(&encoded).map_err(Error::from)?;
        }

        Ok(())
    }

    /// Retrieve binary data from the credential store.
    ///
    /// Automatically reassembles data that was split across multiple entries.
    pub fn get_secret(&self) -> Result<Vec<u8>> {
        // Read part 1 to get total count
        let entry1 = self.part_entry(1)?;
        let data1 = entry1.get_secret().map_err(Error::from)?;
        let (part, total, payload1) = decode_part(&data1)?;

        if part != 1 {
            return Err(Error::CorruptedSecret(format!(
                "expected part 1, got {}",
                part
            )));
        }

        if total == 1 {
            return Ok(payload1);
        }

        // Read remaining parts
        let mut result = payload1;
        for i in 2..=total {
            let entry = self.part_entry(i)?;
            let data = entry.get_secret().map_err(Error::from)?;
            let (part, part_total, payload) = decode_part(&data)?;

            if part != i {
                return Err(Error::CorruptedSecret(format!(
                    "expected part {}, got {}",
                    i, part
                )));
            }
            if part_total != total {
                return Err(Error::CorruptedSecret(format!(
                    "inconsistent total: expected {}, got {}",
                    total, part_total
                )));
            }

            result.extend_from_slice(&payload);
        }

        Ok(result)
    }

    /// Delete the credential from the store.
    ///
    /// This is idempotent - calling it when no credential exists returns Ok(()).
    /// Deletes parts from the end backwards for safe resumption if interrupted.
    pub fn delete_credential(&self) -> Result<()> {
        // Try to read part 1 to get total
        let total = match self.read_part_total(1) {
            Ok(total) => total,
            Err(Error::Keyring(keyring::Error::NoEntry)) => return Ok(()), // Already clean
            Err(e) => return Err(e),
        };

        // Delete from back to front for safe resumption
        for i in (1..=total).rev() {
            let entry = self.part_entry(i)?;
            match entry.delete_credential() {
                Ok(()) => continue,
                Err(keyring::Error::NoEntry) => continue, // Already deleted
                Err(e) => return Err(Error::from(e)),
            }
        }

        Ok(())
    }

    /// Create a keyring entry for the given part number.
    fn part_entry(&self, part: usize) -> Result<keyring::Entry> {
        let part_user = format!("{}.{}", self.user, part);
        keyring::Entry::new(&self.service, &part_user).map_err(Error::from)
    }

    /// Read part 1 and extract just the total count.
    fn read_part_total(&self, part: usize) -> Result<usize> {
        let entry = self.part_entry(part)?;
        let data = entry.get_secret().map_err(Error::from)?;
        let (_, total, _) = decode_part(&data)?;
        Ok(total)
    }
}
