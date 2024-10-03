use std::collections::HashMap;

use super::requests::SignUpPayload;
use crate::{
    constants::BCRYPT_PASSWORD_COST,
    db::types::{ContactType, VerificationStatus},
    error_handlers::error_response,
    requests::Request,
    responses::{CommonError, Error, Response},
    state::AppState,
    tokens::{Flow, FlowToken, TokenType},
    types::{RequestID, TenantID},
    utils::{id::gen_id, text::trim},
};
use axum::{
    body::Body,
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    response,
    response::IntoResponse,
    Extension, Json,
};
use chrono::{Duration, Utc};
use jwt::{Header, SignWithKey, Token};
use scylla::{
    query::Query, serialize::row::SerializeRow, transport::errors::QueryError, QueryResult, Session,
};
use serde_json::{json, Value};
use validator::{ValidateEmail, ValidateLength};
use zxcvbn::Score;

pub async fn sign_up(
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    Extension(RequestID(request_id)): Extension<RequestID>,
    State(state): State<AppState>,
    payload: Result<Json<Request<SignUpPayload>>, JsonRejection>,
) -> response::Response<Body> {
    let response_meta = Some(HashMap::from([
        ("request_id", json!(request_id)),
        ("tenant_id", json!(tenant_id)),
    ]));

    let Json(Request { data: payload, .. }) = match payload {
        Ok(p) => p,
        Err(err) => {
            return CommonError::JsonRejection {
                err,
                request_id,
                tenant_id: Some(tenant_id),
            }
            .into_response()
        }
    };

    let mut errors: Vec<Error> = vec![];

    if let Some(username) = &payload.username {
        if !ValidateLength::validate_length(&username, Some(4), Some(32), None) {
            errors.push(Error::new(
                StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                "Invalid Username",
                "The username must be from 4 to 32 characters long.",
                Some("body.data.username"),
                HashMap::from([
                    ("input", json!(trim(&username, 20))),
                    ("length", json!(username.len())),
                ]),
            ));
        }
    }

    if !ValidateEmail::validate_email(&payload.email) {
        errors.push(Error::new(
            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            "Invalid Email",
            "The email field requires a valid email.",
            Some("body.data.email"),
            HashMap::from([("input", json!(trim(&payload.email, 20)))]),
        ));
    }

    if !ValidateLength::validate_length(&payload.password, None, Some(32), None) {
        errors.push(Error::new(
            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            "Password Too Long",
            "The password must not be more than 32 characters in length.",
            Some("body.data.password"),
            HashMap::from([
                ("input", json!(trim(&payload.password, 20))),
                ("length", json!(payload.password.len())),
            ]),
        ));
    }

    let mut user_inputs: Vec<&str> = vec![&payload.email];

    if let Some(username) = payload.username.as_deref() {
        user_inputs.push(&username);
    }

    if let Some(phone_number) = payload.phone_number.as_deref() {
        user_inputs.push(&phone_number);
    }

    let password_strength = zxcvbn::zxcvbn(&payload.password, &user_inputs[..]);

    if password_strength.score() <= Score::Two {
        errors.push(Error::new(
            StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            "Password Too Weak",
            "The password provided is too weak. To strengthen your password, consider using a combination of letters, numbers, and symbols.",
            Some("body.data.password"),
            HashMap::from([
                ("input", json!(trim(&payload.password, 20))),
                (
                    "suggestions",
                    json!(password_strength
                        .feedback()
                        .unwrap()
                        .suggestions()
                        .iter()
                        .map(|suggestion| { suggestion.to_string() })
                        .collect::<Vec<String>>()),
                ),
                (
                    "score",
                    json!(&password_strength.score().to_string().parse::<u8>().unwrap_or(0)),
                ),
            ]),
        ));
    }

    if errors.len() > 0 {
        let response: Response<Value> = Response::new(None, Some(errors), response_meta, None);

        return (StatusCode::UNPROCESSABLE_ENTITY, Json(response)).into_response();
    }

    let state = state.read().await;

    /// Checks if theres a row that satisfies `check(row)` in the query.
    async fn exists(
        db: &Session,
        query: impl Into<Query>,
        values: impl SerializeRow,
        request_id: String,
        tenant_id: Option<String>,
        error_internal_code: usize,
    ) -> Result<bool, CommonError> {
        let result = db.query_unpaged(query, values).await;

        if let Err(err) = result {
            println!("{err}");
            return Err(CommonError::InternalServerError {
                internal_code: error_internal_code,
                request_id,
                tenant_id,
            });
        }

        let rows_num = result
            .unwrap()
            .rows_num()
            .expect("The query should return rows.");

        Ok(if rows_num != 0 { true } else { false })
    }

    if let Some(username) = &payload.username {
        let username_exists = exists(
            &state.db,
            "SELECT id FROM users_by_username WHERE tenant_id = ? AND username = ?",
            (tenant_id.clone(), &username),
            request_id.clone(),
            Some(tenant_id.clone()),
            2,
        )
        .await;

        if let Err(err) = username_exists {
            return err.into_response();
        } else if let Ok(res) = username_exists {
            if res {
                return error_response(
                    StatusCode::CONFLICT,
                    "Username Already In Use",
                    "There's already a user with this username.",
                    Some("body.data.username"),
                    HashMap::from([("input", json!(trim(&username, 20)))]),
                    request_id.clone(),
                    Some(tenant_id.clone()),
                )
                .into_response();
            }
        }
    }

    let email_exists = exists(
        &state.db,
        "SELECT email FROM users_by_email WHERE tenant_id = ? AND email = ? LIMIT 1",
        (tenant_id.clone(), &payload.email),
        request_id.clone(),
        Some(tenant_id.clone()),
        3,
    )
    .await;

    if let Err(err) = email_exists {
        return err.into_response();
    } else if let Ok(res) = email_exists {
        if res {
            return error_response(
                StatusCode::CONFLICT,
                "Email Already In Use",
                "There's already a user with this email.",
                Some("body.data.email"),
                HashMap::from([("input", json!(trim(&payload.email, 20)))]),
                request_id.clone(),
                Some(tenant_id.clone()),
            )
            .into_response();
        }
    }

    if let Some(phone_number) = &payload.phone_number {
        let phone_number_exists = exists(
            &state.db,
            "SELECT number FROM users_by_phone_number WHERE tenant_id = ? AND number = ? LIMIT 1",
            (tenant_id.clone(), &phone_number),
            request_id.clone(),
            Some(tenant_id.clone()),
            4,
        )
        .await;

        if let Err(err) = phone_number_exists {
            return err.into_response();
        } else if let Ok(res) = phone_number_exists {
            if res {
                return error_response(
                    StatusCode::CONFLICT,
                    "Phone Number Already In Use",
                    "There's already a user with this phone number.",
                    Some("body.data.phone_number"),
                    HashMap::from([("input", json!(trim(&phone_number, 20)))]),
                    request_id.clone(),
                    Some(tenant_id.clone()),
                )
                .into_response();
            }
        }
    }

    let password = bcrypt::hash(&payload.password, (&*BCRYPT_PASSWORD_COST).clone() as u32);

    if let Err(_) = password {
        return CommonError::InternalServerError {
            internal_code: 5,
            request_id,
            tenant_id: Some(tenant_id),
        }
        .into_response();
    }

    let user_id = gen_id(None);

    let mut execution_results: Vec<Result<QueryResult, QueryError>> = vec![
        state.db.query_unpaged(
            "
                INSERT INTO users (
                    tenant_id, id, username, status, roles, login_count, metadata, permissions, password, created_at
                ) VALUES (
                    ?, ?, ?, ?, {}, 0, {}, {}, ?, toTimestamp(now())
                ) USING TTL 172800
            ",
            (
                &tenant_id,
                &user_id,
                &payload.username,
                VerificationStatus::Unverified as i8,
                password.unwrap(),
            )
        ).await,
        state.db.query_unpaged(
            "
                INSERT INTO emails (
                    tenant_id, user_id, email, main, status, type, created_at
                ) VALUES (
                    ?, ?, ?, true, ?, ?, toTimestamp(now())
                ) USING TTL 172800
            ",
            (
                &tenant_id,
                &user_id,
                &payload.email,
                VerificationStatus::Unverified as i8,
                ContactType::Personal as i8,
            )
        ).await
    ];

    if let Some(phone_number) = &payload.phone_number {
        execution_results.push(
            state
                .db
                .query_unpaged(
                    "
                    INSERT INTO phone_numbers (
                        tenant_id, user_id, number, main, status, type, created_at
                    ) VALUES (
                        ?, ?, ?, true, ?, ?, toTimestamp(now())
                    ) USING TTL 172800
                ",
                    (
                        &tenant_id,
                        &user_id,
                        phone_number,
                        VerificationStatus::Unverified as i8,
                        ContactType::Personal as i8,
                    ),
                )
                .await,
        );
    }

    if execution_results.iter().any(|r| r.is_err()) {
        return CommonError::InternalServerError {
            internal_code: 6,
            request_id,
            tenant_id: Some(tenant_id),
        }
        .into_response();
    }

    let claims = FlowToken {
        token_type: TokenType::Flow,
        flow: Flow::SignUpEmailVerification,
        tenant_id: tenant_id.clone(),
        user_id,
        expires_at: (Utc::now() + Duration::days(2)).timestamp(),
    };

    let header = Header {
        algorithm: jwt::AlgorithmType::Hs384,
        ..Header::default()
    };

    let token = Token::new(header, claims).sign_with_key(&state.hmac);

    if let Err(_) = token {
        return CommonError::InternalServerError {
            internal_code: 7,
            request_id,
            tenant_id: Some(tenant_id),
        }
        .into_response();
    }

    (
        StatusCode::CREATED,
        Response::new(
            Some(HashMap::from([
                ("flow_token", json!(token.unwrap().as_str())),
                ("flow", json!(Flow::SignUpEmailVerification)),
            ])),
            None,
            response_meta,
            Some(HashMap::from([("verify", "/auth/sign-up/verify")])),
        ),
    )
        .into_response()
}
