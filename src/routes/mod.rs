use std::collections::HashMap;

use axum::{http::StatusCode, Json};
use chrono::Utc;
use serde_json::Value;

use crate::{responses::{Error, Response}, utils::id::gen_id};

pub mod auth;

pub async fn handler_404() -> (StatusCode, Json<Response<Value>>) {
    (
        StatusCode::NOT_FOUND,
        Json(Response::new(
            None,
            Some(vec![Error {
                code: 404,
                message: "Not found".to_string(),
                detail: "This route does not exist.".to_string(),
                location: "path".to_string(),
                meta: HashMap::new(),
            }]),
            Some(HashMap::from([
                (String::from("request_id"), gen_id(None)),
                (
                    String::from("timestamp"),
                    Utc::now().timestamp_millis().to_string(),
                ),
            ])),
            None,
        )),
    )
}
