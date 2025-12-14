//! Basic usage example: store and retrieve a password.

use keyring_cursed::{Entry, Result};

fn main() -> Result<()> {
    let entry = Entry::new("keyring-cursed-example", "basic-user")?;

    // Store a password
    entry.set_password("my-secret-password")?;
    println!("Password stored.");

    // Retrieve it
    let password = entry.get_password()?;
    println!("Password retrieved: {}", password);

    // Clean up
    entry.delete_credential()?;
    println!("Credential deleted.");

    Ok(())
}
