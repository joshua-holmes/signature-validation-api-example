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

    let result = services::verify_signature(app_state, &verification_data);

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
    let parts: Vec<&str> = payload.message.split(":nonce:").collect();
    if parts.len() != 2 {
        return Err(RequestValidationError::InvalidMessageFormat);
    }
    let nonce = parts[0].to_string();
    let Ok(public_key) = PKey::public_key_from_pem(payload.public_key.as_bytes()) else {
        return Err(RequestValidationError::InvalidPublicKey);
    };
    let Ok(signature) = BASE64_STANDARD.decode(payload.signature.replace("\n", "")) else {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AppState, VerificationData, VerificationRequest, VerificationResponse};
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use hyper::Method;
    use openssl::{pkey::PKey, rsa::Rsa, sign::Signer};
    use serde_json::json;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Helper function to generate a test key pair and signature
    fn generate_test_data(valid_signature: bool) -> (VerificationRequest, VerificationData) {
        let rsa = Rsa::generate(2048).unwrap();
        let private_key = PKey::from_rsa(rsa).unwrap();
        let public_key_pem = String::from_utf8(private_key.public_key_to_pem().unwrap()).unwrap();

        let message = "this_is_my_nonce:nonce:this is my message".to_string();
        let mut signer = Signer::new(openssl::hash::MessageDigest::sha256(), &private_key).unwrap();
        signer.update(message.as_bytes()).unwrap();
        let mut signature = signer.sign_to_vec().unwrap();

        if !valid_signature {
            signature[0] ^= 0xFF; // Corrupt signature
        }

        let signature_b64 = BASE64_STANDARD.encode(&signature);

        let request = VerificationRequest {
            message: message.clone(),
            public_key: public_key_pem.clone(),
            signature: signature_b64,
        };

        let data = VerificationData {
            nonce: "this_is_my_nonce".to_string(),
            public_key: PKey::public_key_from_pem(public_key_pem.as_bytes()).unwrap(),
            signature,
            message,
        };

        (request, data)
    }

    #[tokio::test]
    async fn test_verify_signature_valid() {
        let app_state = Arc::new(AppState::new());
        let router = build_router().with_state(app_state.clone());

        let (request_payload, _) = generate_test_data(true);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&request_payload).unwrap()))
            .unwrap();

        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), 1000000).await.unwrap();
        let response_data: VerificationResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(response_data.valid);
    }

    #[tokio::test]
    async fn test_verify_signature_invalid() {
        let app_state = Arc::new(AppState::new());
        let router = build_router().with_state(app_state.clone());

        let (request_payload, _) = generate_test_data(false);
        let req = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&request_payload).unwrap()))
            .unwrap();

        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), 1000000).await.unwrap();
        let response_data: VerificationResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(!response_data.valid);
    }

    #[tokio::test]
    async fn test_verify_signature_nonce_already_used() {
        let app_state = Arc::new(AppState::new());
        let router = build_router().with_state(app_state.clone());

        let (request_payload, _) = generate_test_data(true);

        // First request (should succeed)
        let req1 = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&request_payload).unwrap()))
            .unwrap();
        let _ = router.clone().oneshot(req1).await.unwrap();

        // Second request (same nonce, should fail)
        let req2 = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&request_payload).unwrap()))
            .unwrap();
        let response = router.clone().oneshot(req2).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = to_bytes(response.into_body(), 1000000).await.unwrap();
        let response_data: VerificationResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(response_data.message, "Nonce already used");
        assert!(!response_data.valid);
    }

    #[tokio::test]
    async fn test_verify_signature_invalid_request_format() {
        let app_state = Arc::new(AppState::new());
        let router = build_router().with_state(app_state.clone());

        let invalid_request = json!({
            "message": "invalid message format", // Missing ":nonce:" delimiter
            "public_key": "some_key",
            "signature": "invalid_signature"
        });

        let req = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(invalid_request.to_string()))
            .unwrap();

        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = to_bytes(response.into_body(), 1000000).await.unwrap();
        let response_data: VerificationResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(response_data.message, "Invalid message format");
        assert!(!response_data.valid);
    }

    #[tokio::test]
    async fn test_verify_signature_invalid_public_key() {
        let app_state = Arc::new(AppState::new());
        let router = build_router().with_state(app_state.clone());

        let invalid_request = json!({
            "message": "test_nonce:nonce:test message",
            "public_key": "invalid key", // Invalid PEM format
            "signature": "validsignature"
        });

        let req = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(invalid_request.to_string()))
            .unwrap();

        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = to_bytes(response.into_body(), 1000000).await.unwrap();
        let response_data: VerificationResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(response_data.message, "Invalid public key");
        assert!(!response_data.valid);
    }

    #[tokio::test]
    async fn test_verify_signature_signature_decode_failure() {
        let app_state = Arc::new(AppState::new());
        let router = build_router().with_state(app_state.clone());
        let valid_public_key = generate_test_data(true).0.public_key;

        let invalid_request = json!({
            "message": "test_nonce:nonce:test message",
            "public_key": valid_public_key,
            "signature": "%%%invalidbase64%%%" // Invalid base64 encoding
        });

        let req = Request::builder()
            .method(Method::POST)
            .uri("/verify")
            .header("content-type", "application/json")
            .body(Body::from(invalid_request.to_string()))
            .unwrap();

        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body_bytes = to_bytes(response.into_body(), 1000000).await.unwrap();
        let response_data: VerificationResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(response_data.message, "Failed to decode signature");
        assert!(!response_data.valid);
    }
}
