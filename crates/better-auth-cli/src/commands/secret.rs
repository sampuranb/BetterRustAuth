// `better-auth secret` — generate a random secret for BETTER_AUTH_SECRET.

use colored::Colorize;
use rand::RngCore;

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let secret = generate_secret();

    println!();
    println!("Add the following to your .env file:");
    println!();
    println!("{}", "# Auth Secret".dimmed());
    println!("{}", format!("BETTER_AUTH_SECRET={secret}").green());
    println!();

    Ok(())
}

/// Generate a cryptographically secure 32-byte hex string.
fn generate_secret() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_length() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_secret_unique() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
    }
}
