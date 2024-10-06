use axum::{
    body::Body,
    extract::{Host, Request, State},
    http::{HeaderMap, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
    Extension,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use regex::Regex;
use serde_json::{json, Value};
use std::{collections::HashMap, io::Read};

use crate::{
    auth::Auth,
    error_handlers::error_response,
    responses::{self, Error},
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
    State(state): State<AppState>,
    Extension(RequestID(request_id)): Extension<RequestID>,
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    Extension(response_meta): Extension<HashMap<&str, Value>>,
    headers: HeaderMap,
    mut req: Request,
    next: Next,
) -> Response<Body> {
    let header = headers.get("authorization");

    if let Some(header) = header {
        let mut value = String::new();

        match header.as_bytes().read_to_string(&mut value) {
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    responses::Response::<Value>::new(
                        None,
                        Some(vec![Error::new(
                            StatusCode::BAD_REQUEST.into(),
                            "Bad Header Format",
                            "The `Authorization` header did not contain valid UTF-8 content.",
                            Some("headers.authorization"),
                            HashMap::new(),
                        )]),
                        Some(response_meta),
                        None,
                    ),
                )
                    .into_response()
            }
            _ => {}
        }

        if Regex::new(r"^Bearer [A-Za-z0-9_-]{86}$")
            .unwrap()
            .is_match(value.as_str())
        {
            let state = state.read().await;
            let token = value
                .as_str()
                .split_ascii_whitespace()
                .collect::<Vec<&str>>()[1];

            let user_id = match state
                .db
                .query_unpaged(
                    "SELECT user_id FROM api_tokens WHERE tenant_id = ? AND api_token = ? AND is_refresh = false LIMIT 1",
                    (&tenant_id, &URL_SAFE_NO_PAD.decode(token).unwrap()
                )
            ).await {
                Ok(result) => {
                    match result.first_row_typed::<(String,)>() {
                        Ok((user_id,)) => user_id,
                        Err(_) => {
                            return (
                                StatusCode::UNAUTHORIZED,
                                responses::Response::<Value>::new(
                                    None,
                                    Some(vec![
                                        Error::new(
                                            StatusCode::UNAUTHORIZED.into(),
                                            "Unauthorized",
                                            "The provided token is invalid. Check that it hasn't expired.",
                                            Some("headers.authorization"),
                                            HashMap::from([("input", json!(token))])
                                        )
                                    ]),
                                    Some(response_meta),
                                    None
                                )
                            ).into_response()
                        }
                    }
                },
                Err(_) => return responses::CommonError::InternalServerError { request_id, tenant_id: Some(tenant_id) }.into_response()
            };

            req.extensions_mut().insert(Auth {
                user_id: Some(user_id),
                token: Some(token.to_string()),
                scopes: vec![],
                client_id: None,
            });

            return next.run(req).await;
        } else {
            return (
                StatusCode::BAD_REQUEST,
                responses::Response::<Value>::new(
                    None,
                    Some(vec![Error::new(
                        StatusCode::BAD_REQUEST.into(),
                        "Invalid Header",
                        "The `Authorization` header is not correctly formatted.",
                        Some("headers.authorization"),
                        HashMap::from([("input", json!(value))]),
                    )]),
                    Some(response_meta),
                    None,
                ),
            )
                .into_response();
        }
    } else {
        req.extensions_mut().insert(Auth {
            user_id: None,
            token: None,
            scopes: vec![],
            client_id: None,
        });

        return next.run(req).await;
    }
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
        .query_unpaged(
            "SELECT tenant_id FROM tenants_by_host WHERE host = ?",
            (&host,),
        )
        .await;

    if let Err(_) = result {
        return responses::CommonError::InternalServerError {
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

pub async fn response_meta(
    Extension(RequestID(request_id)): Extension<RequestID>,
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    mut req: Request,
    next: Next,
) -> Response<Body> {
    req.extensions_mut().insert(HashMap::from([
        ("tenant_id", json!(tenant_id)),
        ("request_id", json!(request_id)),
    ]));

    next.run(req).await
}
