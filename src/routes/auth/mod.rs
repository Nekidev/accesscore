mod handlers;
mod requests;
mod responses;

use crate::state::AppState;
use axum::{routing::post, Router};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sign-up", post(handlers::sign_up))
        .route("/sign-in", post(handlers::sign_in))
}
