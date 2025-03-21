use std::sync::Arc;

use axum::http::{HeaderValue, StatusCode};
use axum::{Json, Router, extract::State, routing::post};
use base64::{Engine, prelude::BASE64_STANDARD};
use openssl::pkey::PKey;
use tower_http::cors::CorsLayer;
use types::{
    AppState, VerificationData, VerificationRequest, VerificationResponse, VerificationResult,
};

mod services;
mod types;

/// Selected port that the server will run on
const PORT: u16 = 3000;

#[tokio::main]
async fn main() {
    let app_state = Arc::new(AppState::new());

    let cors = CorsLayer::new()
        .allow_origin(HeaderValue::from_str("http://localhost").expect("Failed to setup CORS"));

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", PORT))
        .await
        .unwrap_or_else(|e| panic!("Axum failed to bind to port {}:\n{}", PORT, e));

    let app = Router::new()
        .route("/verify", post(verify_signature))
        .layer(cors)
        .with_state(app_state);

    println!("Server running on http://localhost:{}", PORT);
    axum::serve(listener, app)
        .await
        .expect("Failed to start Axum server");
}

async fn verify_signature(
    State(app_state): State<Arc<AppState>>,
    Json(payload): Json<VerificationRequest>,
) -> (StatusCode, Json<VerificationResponse>) {
    // Prepare data for verification
    let parts: Vec<&str> = payload.message.split("-nonce:").collect();
    if parts.len() != 2 {
        return (
            StatusCode::BAD_REQUEST,
            Json(VerificationResponse {
                valid: false,
                message: "Invalid message format".to_string(),
            }),
        );
    }
    let nonce = parts[0].to_string();
    let Ok(public_key) = PKey::public_key_from_pem(payload.public_key.as_bytes()).map_err(|e| {
        let msg = "Invalid public key";
        println!("{msg}:\n{e}");
    }) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(VerificationResponse {
                valid: false,
                message: "Invalid public key".to_string(),
            }),
        );
    };
    let Ok(signature) = BASE64_STANDARD.decode(payload.signature).map_err(|e| {
        let msg = "Failed to decode base64 signature";
        println!("{msg}:\n{e}");
    }) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(VerificationResponse {
                valid: false,
                message: "Failed to decode base64 signature".to_string(),
            }),
        );
    };
    let verification_data = VerificationData {
        nonce,
        public_key,
        signature,
        message: payload.message,
    };

    // Verify signature
    let result = services::verify_signature(app_state, verification_data);

    // Send response
    let valid = matches!(result, Ok(VerificationResult::SignatureValid));
    let (status_code, message) = match result {
        Ok(ok) => (StatusCode::OK, ok.to_string()),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    (status_code, Json(VerificationResponse { valid, message }))
}
