# keyring-cursed

A wrapper over [keyring](https://crates.io/crates/keyring) that stripes large secrets across multiple credential entries.

## Why?

Platform credential stores have size limits per entry (Windows ~2.5KB, macOS ~16KB). This crate transparently splits large secrets across multiple entries and reassembles them on retrieval.

## Usage

```rust
use keyring_cursed::{Entry, Result};

fn main() -> Result<()> {
    let entry = Entry::new("my-service", "my-user")?;

    // Store a secret (automatically splits if too large)
    entry.set_password("my-secret-password")?;

    // Retrieve it (automatically reassembles)
    let password = entry.get_password()?;

    // Clean up
    entry.delete_credential()?;

    Ok(())
}
```

## Features

- **Automatic chunking**: Large secrets are split across multiple keyring entries
- **Platform-aware**: Chunk sizes are optimized per platform
- **Idempotent delete**: Safe to call multiple times, resumes interrupted cleanup
- **Minimal overhead**: Small secrets use a single entry

## Storage Format

Secrets are stored with user names like `{user}.1`, `{user}.2`, etc. Each part contains a header `{part}/{total}|` followed by the payload.

## License

MIT
