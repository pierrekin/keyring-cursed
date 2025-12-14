//! Example demonstrating storage of a large secret that gets chunked.

use keyring_cursed::{max_chunk_size, Entry, Result};

fn main() -> Result<()> {
    let chunk_size = max_chunk_size();
    println!("Platform chunk size: {} bytes", chunk_size);

    // Create a secret larger than one chunk
    let secret_size = chunk_size * 3 + 500;
    let large_secret: Vec<u8> = (0..secret_size).map(|i| (i % 256) as u8).collect();
    println!("Storing secret of {} bytes (~{} chunks)", secret_size, secret_size / chunk_size + 1);

    let entry = Entry::new("keyring-cursed-example", "large-secret-user")?;

    // Store the large secret
    entry.set_secret(&large_secret)?;
    println!("Secret stored.");

    // Retrieve it
    let retrieved = entry.get_secret()?;
    println!("Secret retrieved: {} bytes", retrieved.len());

    // Verify integrity
    assert_eq!(large_secret, retrieved);
    println!("Integrity verified!");

    // Clean up
    entry.delete_credential()?;
    println!("Credential deleted.");

    Ok(())
}
