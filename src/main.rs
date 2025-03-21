#![feature(assert_matches)]

use std::sync::Arc;

use axum::http::HeaderValue;
use tower_http::cors::CorsLayer;
use types::AppState;

mod handlers;
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

    let app = handlers::build_router().layer(cors).with_state(app_state);

    println!("Server running on http://localhost:{}", PORT);
    axum::serve(listener, app)
        .await
        .expect("Failed to start Axum server");
}
