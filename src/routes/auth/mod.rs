mod handlers;
mod requests;

use crate::state::AppState;
use axum::{routing::post, Router};

pub fn router() -> Router<AppState> {
    Router::new().route("/auth/sign-up", post(handlers::sign_up))
}
