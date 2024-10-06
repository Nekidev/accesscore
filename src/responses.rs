#![allow(dead_code)]

use std::collections::HashMap;

use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{self, IntoResponse},
    Json,
};
use serde::Serialize;
use serde_json::Value;

use crate::error_handlers::error_response;

#[derive(Debug, Serialize)]
pub struct Response<T> {
    data: Option<T>,
    errors: Vec<Error>,
    meta: HashMap<String, Value>,
    links: HashMap<String, String>,
}

impl<T> Response<T> {
    pub fn new(
        data: Option<T>,
        errors: Option<Vec<Error>>,
        meta: Option<HashMap<&str, Value>>,
        links: Option<HashMap<&str, &str>>,
    ) -> Self {
        Self {
            data,
            errors: errors.unwrap_or(vec![]),
            meta: meta
                .unwrap_or(HashMap::new())
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone())) // Convert key to String and dereference value
                .collect(),
            links: links
                .unwrap_or(HashMap::new())
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string())) // Convert key to String and dereference value
                .collect(),
        }
    }
}

impl<T> IntoResponse for Response<T>
where
    T: Serialize,
{
    fn into_response(self) -> response::Response {
        Json(self).into_response()
    }
}

#[derive(Debug, Serialize)]
pub struct Error {
    pub code: u16,
    pub message: String,
    pub detail: String,
    pub location: Option<String>,
    pub meta: HashMap<String, Value>,
}

impl Error {
    pub fn new(
        code: u16,
        message: &str,
        detail: &str,
        location: Option<&str>,
        meta: HashMap<&str, Value>,
    ) -> Self {
        Self {
            code,
            message: message.to_string(),
            detail: detail.to_string(),
            location: location.map(|s| s.to_string()),
            meta: meta
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone())) // Convert key to String and dereference value
                .collect(),
        }
    }
}

pub enum CommonError {
    JsonRejection {
        err: JsonRejection,
        request_id: String,
        tenant_id: Option<String>,
    },
    InternalServerError {
        request_id: String,
        tenant_id: Option<String>,
    },
}

impl response::IntoResponse for CommonError {
    fn into_response(self) -> response::Response {
        let data: (StatusCode, Json<Response<Value>>) = match self {
            Self::JsonRejection {
                err,
                request_id,
                tenant_id,
            } => match err {
                JsonRejection::MissingJsonContentType(err) => error_response(
                    err.status(),
                    "Missing JSON Content-Type Header",
                    "The request must contain a Content-Type: application/json header.",
                    Some("headers"),
                    HashMap::new(),
                    request_id,
                    tenant_id,
                ),
                JsonRejection::JsonDataError(err) => error_response(
                    err.status(),
                    "Invalid Request Body Schema",
                    "The request body doesn't follow the endpoint's schema.",
                    Some("body"),
                    HashMap::new(),
                    request_id,
                    tenant_id,
                ),
                JsonRejection::JsonSyntaxError(err) => error_response(
                    err.status(),
                    "Invalid JSON Syntax",
                    "The request body contains invalid JSON.",
                    Some("body"),
                    HashMap::new(),
                    request_id,
                    tenant_id,
                ),
                JsonRejection::BytesRejection(err) => error_response(
                    err.status(),
                    "Bytes Rejection",
                    "The request body's JSON could not be extracted.",
                    Some("body"),
                    HashMap::new(),
                    request_id,
                    tenant_id,
                ),
                _ => error_response(
                    StatusCode::BAD_REQUEST,
                    "Unknown JSON Error",
                    "An unknown error occurred parsing the request body's JSON.",
                    Some("body"),
                    HashMap::new(),
                    request_id,
                    tenant_id,
                ),
            },
            Self::InternalServerError {
                request_id,
                tenant_id,
            } => error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "An unexpected internal error occured.",
                None,
                HashMap::new(),
                request_id,
                tenant_id,
            ),
        };

        data.into_response()
    }
}

pub type ResponseMeta<'a> = HashMap<&'a str, Value>;
