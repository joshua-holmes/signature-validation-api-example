//! Module that handles receiving and sending requests. In a larger project, the structure would look more like:
//! handlers
//! ├-- mod.rs
//! ├-- verify.rs
//! ├-- another_namespace.rs
//!
//! Then `mod.rs` would hold the `build_router()` function that builds routes using handlers from the other submodules.

use std::sync::Arc;

use crate::{
    services,
    types::{
        AppState, RequestValidationError, VerificationData, VerificationRequest,
        VerificationResponse, VerificationResult,
    },
};
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use base64::{Engine, prelude::BASE64_STANDARD};
use openssl::pkey::PKey;

pub fn build_router() -> Router<Arc<AppState>> {
    Router::new().route("/verify", post(verify_signature))
}

async fn verify_signature(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<VerificationRequest>,
) -> (StatusCode, Json<VerificationResponse>) {
    let verification_data = match validate_and_transform(payload) {
        Ok(data) => data,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(VerificationResponse {
                    valid: false,
                    message: err.to_string(),
                }),
            );
        }
    };

    let result = services::verify_signature(app_state, verification_data);

    let valid = matches!(result, Ok(VerificationResult::SignatureValid));
    let (status_code, message) = match result {
        Ok(ok) => (StatusCode::OK, ok.to_string()),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    (status_code, Json(VerificationResponse { valid, message }))
}

/// Validate and prepare data for signature verification
fn validate_and_transform(
    payload: VerificationRequest,
) -> Result<VerificationData, RequestValidationError> {
    let parts: Vec<&str> = payload.message.split("-nonce:").collect();
    if parts.len() != 2 {
        return Err(RequestValidationError::InvalidMessageFormat);
    }
    let nonce = parts[0].to_string();
    let Ok(public_key) = PKey::public_key_from_pem(payload.public_key.as_bytes()) else {
        return Err(RequestValidationError::InvalidPublicKey);
    };
    let Ok(signature) = BASE64_STANDARD.decode(payload.signature) else {
        return Err(RequestValidationError::FailedToDecodeSignature);
    };
    let verification_data = VerificationData {
        nonce,
        public_key,
        signature,
        message: payload.message,
    };

    Ok(verification_data)
}
