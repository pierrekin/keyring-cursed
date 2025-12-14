//! Example demonstrating idempotent delete behavior.

use keyring_cursed::{Entry, Result};

fn main() -> Result<()> {
    let entry = Entry::new("keyring-cursed-example", "idempotent-user")?;

    // Delete is safe to call even when nothing exists
    entry.delete_credential()?;
    println!("First delete (nothing existed): OK");

    // Store something
    entry.set_password("temporary")?;
    println!("Password stored.");

    // Delete it
    entry.delete_credential()?;
    println!("Second delete (removed credential): OK");

    // Delete again - still safe
    entry.delete_credential()?;
    println!("Third delete (already gone): OK");

    Ok(())
}
