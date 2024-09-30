use std::collections::HashMap;

use axum::{extract::State, routing::get, Json, Router};
use serde_json::{json, Value};

use crate::{responses::Response, state::AppState};

pub fn router() -> Router<AppState> {
    Router::new().route("/test/init", get(init))
}

pub async fn init(State(state): State<AppState>) -> Json<Response<HashMap<String, Value>>> {
    let state = state.lock().await;

    let mut redis_conn = state.redis.acquire().await.unwrap();

    let new_incr: i32 = redis::cmd("INCR")
        .arg("incr")
        .query_async(&mut redis_conn)
        .await
        .unwrap();

    Json(Response::new(
        Some(HashMap::from([(String::from("new_incr"), json!(new_incr))])),
        None,
        None,
        None,
    ))
}
