use std::sync::Arc;

use openssl::{hash::MessageDigest, sign::Verifier};

use crate::types::{AppState, VerificationData, VerificationError, VerificationResult};

/// Verifies signature from message and public key.
///
/// If no verification errors occurred, returns `true` if signature is valid, `false` otherwise.
pub fn verify_signature(
    app_state: Arc<AppState>,
    data: VerificationData,
) -> Result<VerificationResult, VerificationError> {
    // Check if nonce has previously been used
    if !app_state.insert_nonce(data.nonce).map_err(|e| {
        println!("Poisoned mutex when inserting nonce:\n{}", e);
        VerificationError::NonceMutextPoisoned
    })? {
        return Ok(VerificationResult::NonceAlreadyUsed);
    }

    // Setup verifier
    let mut verifier = Verifier::new(MessageDigest::sha256(), &data.public_key).map_err(|e| {
        println!("Failed to create verifier:\n{}", e);
        VerificationError::OpenSslFailed
    })?;
    verifier.update(data.message.as_bytes()).map_err(|e| {
        println!("Failed to update verifier:\n{}", e);
        VerificationError::OpenSslFailed
    })?;

    // Verify
    let is_valid = verifier.verify(&data.signature).map_err(|e| {
        println!("Failed to verify:\n{}", e);
        VerificationError::OpenSslFailed
    })?;

    Ok(if is_valid {
        VerificationResult::SignatureValid
    } else {
        VerificationResult::SignatureInvalid
    })
}
