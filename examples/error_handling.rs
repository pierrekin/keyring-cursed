use keyring_cursed::{Entry, Error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let entry = Entry::new("example-service", "example-user")?;

    // Try to get a password that doesn't exist
    match entry.get_password() {
        Ok(password) => {
            println!("Found password: {}", password);
        }
        Err(Error::NoEntry) => {
            println!("No password found - this is expected for a new entry");

            // Set a password
            entry.set_password("my-secret-password")?;
            println!("Password stored successfully");

            // Now retrieve it
            let password = entry.get_password()?;
            println!("Retrieved password: {}", password);

            // Clean up
            entry.delete_credential()?;
            println!("Credential deleted");
        }
        Err(e) => {
            println!("Unexpected error: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}