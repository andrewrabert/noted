use std::sync::OnceLock;

use scrypt::Scrypt;
use scrypt::password_hash::phc::PasswordHash;
use scrypt::password_hash::{PasswordHasher, PasswordVerifier};

pub fn hash_password(password: &str) -> String {
    Scrypt::new()
        .hash_password(password.as_bytes())
        .expect("scrypt hashing with a generated salt")
        .to_string()
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(hash) => Scrypt::new()
            .verify_password(password.as_bytes(), &hash)
            .is_ok(),
        Err(_) => false,
    }
}

pub fn verify_dummy() {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| hash_password("noted dummy timing password"));
    let _ = verify_password("", dummy);
}
