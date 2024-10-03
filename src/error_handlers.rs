use std::collections::HashMap;

use axum::{extract, http::StatusCode, Extension, Json};
use serde_json::{json, Value};

use crate::{
    responses::{Error, Response},
    types::{RequestID, TenantID},
};

type ResponseWithStatusCode = (StatusCode, Json<Response<Value>>);

pub async fn handler_404(
    Extension(RequestID(request_id)): Extension<RequestID>,
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    request: extract::Request,
) -> ResponseWithStatusCode {
    error_response(
        StatusCode::NOT_FOUND,
        "Not Found",
        "This route does not exist.",
        Some("path"),
        HashMap::from([("path", json!(request.uri().path()))]),
        request_id,
        Some(tenant_id),
    )
}

// Builds an error response out of an error.
pub fn error_response(
    status: StatusCode,
    message: &str,
    detail: &str,
    location: Option<&str>,
    meta: HashMap<&str, Value>,
    request_id: String,
    tenant_id: Option<String>,
) -> ResponseWithStatusCode {
    (
        status,
        Json(Response::new(
            None,
            Some(vec![Error::new(
                status.as_u16(),
                message,
                detail,
                location,
                meta,
            )]),
            Some(HashMap::from([
                ("request_id", json!(request_id)),
                ("tenant_id", json!(tenant_id)),
            ])),
            None,
        )),
    )
}
