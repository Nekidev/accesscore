#![allow(dead_code)]

use std::collections::HashMap;

use axum::{extract::rejection::JsonRejection, http::StatusCode, response, Json};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct Response<T> {
    data: Option<T>,
    errors: Vec<Error>,
    meta: HashMap<String, String>,
    links: HashMap<String, String>,
}

impl<T> Response<T> {
    pub fn new(
        data: Option<T>,
        errors: Option<Vec<Error>>,
        meta: Option<HashMap<String, String>>,
        links: Option<HashMap<String, String>>,
    ) -> Self {
        Self {
            data,
            errors: errors.unwrap_or(vec![]),
            meta: meta.unwrap_or(HashMap::new()),
            links: links.unwrap_or(HashMap::new()),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Error {
    pub code: u16,
    pub message: String,
    pub detail: String,
    pub location: String,
    pub meta: HashMap<String, Value>,
}

pub enum CommonError {
    JsonRejection(JsonRejection),
}

impl From<JsonRejection> for CommonError {
    fn from(rejection: JsonRejection) -> Self {
        CommonError::JsonRejection(rejection)
    }
}

impl response::IntoResponse for CommonError {
    fn into_response(self) -> response::Response {
        let data: (StatusCode, Json<Response<Value>>) = match self {
            Self::JsonRejection(JsonRejection::MissingJsonContentType(err)) => (
                err.status(),
                Json(Response::new(
                    None,
                    Some(vec![Error {
                        code: err.status().as_u16(),
                        message: "Missing JSON Content-Type Header".to_string(),
                        detail: "The request must contain a Content-Type: application/json header."
                            .to_string(),
                        location: "headers.content_type".to_string(),
                        meta: HashMap::new(),
                    }]),
                    None,
                    None,
                )),
            ),
            Self::JsonRejection(JsonRejection::JsonDataError(err)) => (
                err.status(),
                Json(Response::new(
                    None,
                    Some(vec![Error {
                        code: err.status().as_u16(),
                        message: "Invalid Request Body Schema".to_string(),
                        detail: "The request body doesn't follow the endpoint's schema."
                            .to_string(),
                        location: "body".to_string(),
                        meta: HashMap::new(),
                    }]),
                    None,
                    None,
                )),
            ),
            Self::JsonRejection(JsonRejection::JsonSyntaxError(err)) => (
                err.status(),
                Json(Response::new(
                    None,
                    Some(vec![Error {
                        code: err.status().as_u16(),
                        message: "Invalid JSON Syntax".to_string(),
                        detail: "The request body contains invalid JSON.".to_string(),
                        location: "body".to_string(),
                        meta: HashMap::new(),
                    }]),
                    None,
                    None,
                )),
            ),
            Self::JsonRejection(JsonRejection::BytesRejection(err)) => (
                err.status(),
                Json(Response::new(
                    None,
                    Some(vec![Error {
                        code: err.status().as_u16(),
                        message: "Bytes Rejection".to_string(),
                        detail: "The request body's JSON could not be extracted.".to_string(),
                        location: "body".to_string(),
                        meta: HashMap::new(),
                    }]),
                    None,
                    None,
                )),
            ),
            Self::JsonRejection(_) => (
                StatusCode::BAD_REQUEST,
                Json(Response::new(
                    None,
                    Some(vec![Error {
                        code: 400,
                        message: "Unknown JSON Error".to_string(),
                        detail: "An unknown error occurred parsing the request body's JSON.".to_string(),
                        location: "body".to_string(),
                        meta: HashMap::new(),
                    }]),
                    None,
                    None,
                )),
            )
        };

        data.into_response()
    }
}
