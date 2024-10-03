use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Host, Request, State},
    http::{Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Extension, Json,
};
use serde_json::{json, Value};

use crate::{
    error_handlers::error_response,
    responses::{self, CommonError},
    state::AppState,
    types::{RequestID, TenantID},
    utils::id::gen_id,
};

pub async fn request_id(mut req: Request, next: Next) -> Response<Body> {
    let id = gen_id(None);

    req.extensions_mut().insert(RequestID(id));

    next.run(req).await
}

pub async fn authentication(
    State(_state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response<Body>, Json<responses::Response<Value>>> {
    Ok(next.run(request).await)
}

pub async fn tenant(
    Extension(RequestID(request_id)): Extension<RequestID>,
    State(state): State<AppState>,
    Host(host): Host,
    mut req: Request,
    next: Next,
) -> Response<Body> {
    let state = state.read().await;

    let result = state
        .db
        .query_unpaged("SELECT id FROM tenants_by_host WHERE host = ?", (&host,))
        .await;

    if let Err(_) = result {
        return CommonError::InternalServerError {
            internal_code: 1,
            request_id,
            tenant_id: None,
        }
        .into_response();
    }

    let result = result.unwrap();

    if result.rows_num().unwrap() == 0 {
        return error_response(
            StatusCode::NOT_FOUND,
            "Host Not Found",
            "The host name is not linked to any AccessCore tenant.",
            Some("headers.host"),
            HashMap::from([
                ("request_id", json!(request_id)),
                ("tenant_id", Value::Null),
            ]),
            request_id,
            None,
        )
        .into_response();
    }

    let (tenant_id,): (String,) = result
        .first_row()
        .unwrap()
        .into_typed::<(String,)>()
        .unwrap();

    req.extensions_mut().insert(TenantID(tenant_id));

    next.run(req).await
}
