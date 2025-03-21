//! A module containing all custom types relevant to this application. In a larger application, we could namespace
//! endpoints and have one `types` module for each namespace.

use std::{
    collections::HashSet,
    fmt::Display,
    sync::{Mutex, MutexGuard, PoisonError},
};

use openssl::pkey::{PKey, Public};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct VerificationRequest {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct VerificationResponse {
    pub valid: bool,
    pub message: String,
}

pub struct VerificationData {
    pub nonce: String,
    pub message: String,
    pub public_key: PKey<Public>,
    pub signature: Vec<u8>,
}

/// Indicates verification process is complete and what the result is
pub enum VerificationResult {
    SignatureValid,
    SignatureInvalid,
    NonceAlreadyUsed,
}
impl Display for VerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                VerificationResult::SignatureValid => "Signature valid",
                VerificationResult::SignatureInvalid => "Signature invalid",
                VerificationResult::NonceAlreadyUsed => "Nonce already used",
            }
        )
    }
}

/// Represents a variety of errors that could occur during signature validation
pub enum VerificationError {
    OpenSslFailed,
    NonceMutextPoisoned,
}
impl Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                VerificationError::NonceMutextPoisoned => "Nonce mutext poisoned",
                VerificationError::OpenSslFailed => "OpenSSL failed",
            }
        )
    }
}

/// Shared state to track used nonces
pub struct AppState {
    // Keeping field private to make it impossible to delete a nonce.
    // NOTE: If this was not an example project, this data would be kept in a database for persistence, instead of
    // in-memory.
    used_nonces: Mutex<HashSet<String>>,
}
impl AppState {
    pub fn new() -> Self {
        AppState {
            used_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Insert nonce into a `HashSet`, marking it as used.
    ///
    /// Returns whether the value was newly inserted, just as `HashSet::insert` does. That is:
    /// * If the set did not previously contain this value, `true` is returned.
    /// * If the set already contained this value, `false` is returned,
    ///   and the set is not modified: original value is not replaced,
    ///   and the value passed as argument is dropped.
    pub fn insert_nonce(
        &self,
        value: String,
    ) -> Result<bool, PoisonError<MutexGuard<'_, HashSet<String>>>> {
        Ok(self.used_nonces.lock()?.insert(value))
    }
}
