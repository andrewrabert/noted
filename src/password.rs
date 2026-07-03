use std::sync::OnceLock;

use scrypt::password_hash::rand_core::OsRng;
use scrypt::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use scrypt::Scrypt;

pub fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Scrypt
        .hash_password(password.as_bytes(), &salt)
        .expect("scrypt hashing with a valid salt")
        .to_string()
}

pub fn verify_password(password: &str, stored: &str) -> bool {
    match PasswordHash::new(stored) {
        Ok(hash) => Scrypt.verify_password(password.as_bytes(), &hash).is_ok(),
        Err(_) => false,
    }
}

pub fn verify_dummy() {
    static DUMMY: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY.get_or_init(|| hash_password("noted dummy timing password"));
    let _ = verify_password("", dummy);
}
