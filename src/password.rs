use crate::AuthError;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use sha2::{Digest, Sha256};

const MIN_PASSWORD_CHARS: usize = 8;

pub(crate) fn hash_new_password(password: &str) -> Result<String, AuthError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AuthError::InvalidParams(
            "password must contain at least 8 characters".to_owned(),
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::PasswordHash(error.to_string()))
}

/// Binds a reset token to the current password hash so it dies after use.
pub(crate) fn fingerprint(password_hash: &str) -> String {
    Sha256::digest(password_hash.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
