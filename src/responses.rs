#![allow(dead_code)]

use std::collections::HashMap;

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

#[derive(Debug, Serialize)]
pub struct IndexResponse {
    pub docs: String,
}
