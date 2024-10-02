use std::collections::HashMap;

use axum::{extract, http::StatusCode, Extension, Json};
use serde_json::{json, Value};

use crate::{
    responses::{Error, Response},
    types::{RequestID, TenantID},
};

pub async fn handler_404(
    Extension(request_id): Extension<RequestID>,
    Extension(tenant_id): Extension<TenantID>,
    request: extract::Request,
) -> (StatusCode, Json<Response<Value>>) {
    (
        StatusCode::NOT_FOUND,
        Json(Response::new(
            None,
            Some(vec![Error {
                code: 404,
                message: "Not found".to_string(),
                detail: "This route does not exist.".to_string(),
                location: "path".to_string(),
                meta: HashMap::from([("path".to_string(), json!(request.uri().path()))]),
            }]),
            Some(HashMap::from([
                ("request_id".to_string(), request_id.id),
                ("tenant_id".to_string(), tenant_id.id),
            ])),
            None,
        )),
    )
}
