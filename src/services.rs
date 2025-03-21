//! Module that handles the business logic of the application. In a larger project, this would be split into submodules

use std::sync::Arc;

use openssl::{hash::MessageDigest, sign::Verifier};

use crate::types::{AppState, VerificationData, VerificationError, VerificationResult};

/// Verifies signature from message and public key.
///
/// If no verification errors occurred, returns `true` if signature is valid, `false` otherwise.
pub fn verify_signature(
    app_state: Arc<AppState>,
    data: &VerificationData,
) -> Result<VerificationResult, VerificationError> {
    // Check if nonce has previously been used
    if !app_state.insert_nonce(data.nonce.clone()).map_err(|e| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AppState, VerificationData, VerificationResult};
    use openssl::{pkey::PKey, rsa::Rsa, sign::Signer};
    use std::{
        assert_matches::assert_matches,
        sync::Arc,
    };

    /// Helper function to generate test keys and a valid signature
    fn generate_test_data(valid_signature: bool) -> VerificationData {
        let rsa = Rsa::generate(2048).unwrap();
        let private_key = PKey::from_rsa(rsa).unwrap();
        let public_key = private_key.public_key_to_pem().unwrap();

        let message = "test message".to_string();
        let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
        signer.update(message.as_bytes()).unwrap();
        let mut signature = signer.sign_to_vec().unwrap();

        if !valid_signature {
            signature[0] ^= 0xFF; // Corrupt the signature to make it invalid
        }

        VerificationData {
            nonce: "unique_nonce".to_string(),
            message,
            signature,
            public_key: PKey::public_key_from_pem(&public_key).unwrap(),
        }
    }

    #[test]
    fn test_verify_signature_valid() {
        let app_state = Arc::new(AppState::new());
        let data = generate_test_data(true);

        let result = verify_signature(app_state, &data).unwrap();
        assert_matches!(result, VerificationResult::SignatureValid);
    }

    #[test]
    fn test_verify_signature_invalid() {
        let app_state = Arc::new(AppState::new());
        let data = generate_test_data(false);

        let result = verify_signature(app_state, &data).unwrap();
        assert_matches!(result, VerificationResult::SignatureInvalid);
    }

    #[test]
    fn test_verify_signature_nonce_already_used() {
        let app_state = Arc::new(AppState::new());
        let data = generate_test_data(true);

        let result = verify_signature(Arc::clone(&app_state), &data).unwrap();
        // First call should succeed
        assert_matches!(result, VerificationResult::SignatureValid);

        // Second call should detect the reused nonce
        let result = verify_signature(app_state, &data).unwrap();
        assert_matches!(result, VerificationResult::NonceAlreadyUsed);
    }
}
