use keyring_cursed::{Entry, Error};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let entry = Entry::new("persistence-test", "test-user")?;

    println!("Step 1: Verify entry doesn't exist initially");
    match entry.get_password() {
        Err(Error::NoEntry) => println!("✓ Entry doesn't exist (as expected)"),
        Ok(password) => println!("⚠ Entry already exists with password: {}", password),
        Err(e) => return Err(e.into()),
    }

    println!("\nStep 2: Store a password");
    entry.set_password("test-persistence-password")?;
    println!("✓ Password stored");

    println!("\nStep 3: Retrieve the password immediately");
    let retrieved = entry.get_password()?;
    println!("✓ Retrieved: {}", retrieved);

    println!("\nStep 4: Leave the password in keychain for manual verification");
    println!("Run this command to verify it's actually in the keychain:");
    println!("security find-generic-password -s 'persistence-test' -a 'test-user.1' -w");
    println!("\nTo clean up later, run:");
    println!("security delete-generic-password -s 'persistence-test' -a 'test-user.1'");

    Ok(())
}

