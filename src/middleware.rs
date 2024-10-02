use std::collections::HashMap;

use axum::{
    body::Body,
    extract::{Host, Request, State},
    http::{Response, StatusCode},
    middleware::Next,
    Json,
};
use serde_json::{json, Value};

use crate::{
    responses::{self, Error},
    state::AppState,
    types::{RequestID, TenantID},
    utils::id::gen_id,
};

pub async fn request_id(mut req: Request, next: Next) -> Response<Body> {
    let id = gen_id(None);

    req.extensions_mut().insert(RequestID { id });

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
    State(state): State<AppState>,
    Host(host): Host,
    mut req: Request,
    next: Next,
) -> Result<Response<Body>, (StatusCode, Json<responses::Response<Value>>)> {
    let state = state.lock().await;

    let result = state
        .db
        .query_unpaged("SELECT id FROM tenants_by_host WHERE host = ?", (&host,))
        .await;

    if let Err(_) = result {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(responses::Response::new(
                None,
                Some(vec![Error {
                    code: 500,
                    message: "Server Internal Error".to_string(),
                    detail: "An error occurred in the server.".to_string(),
                    location: "server".to_string(),
                    meta: HashMap::new(),
                }]),
                None,
                None,
            )),
        ));
    }

    let result = result.unwrap();

    if result.rows_num().unwrap() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(responses::Response::new(
                None,
                Some(vec![Error {
                    code: 404,
                    message: "Host Not Found".to_string(),
                    detail: "The host name is not linked to any AccessCore tenant.".to_string(),
                    location: "headers.host".to_string(),
                    meta: HashMap::from([("host".to_string(), json!(host))]),
                }]),
                None,
                None,
            )),
        ));
    }

    let (tenant_id,): (String,) = result
        .first_row()
        .unwrap()
        .into_typed::<(String,)>()
        .unwrap();

    req.extensions_mut().insert(TenantID { id: tenant_id });

    Ok(next.run(req).await)
}
