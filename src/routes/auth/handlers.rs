use super::requests::{SignInPayload, SignUpPayload};
use crate::{
    constants::BCRYPT_PASSWORD_COST,
    db::types::{ContactType, VerificationStatus},
    error_handlers::error_response,
    requests::Request,
    responses::{CommonError, Error, Response, ResponseMeta},
    routes::auth::responses::SignInResponse,
    state::AppState,
    tokens::{token, Flow, FlowToken, TokenType},
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
use base64::engine::{general_purpose::URL_SAFE, Engine as _};
use chrono::{Duration, Utc};
use jwt::{Header, SignWithKey, Token};
use scylla::{
    batch::Batch,
    query::Query,
    serialize::{row::SerializeRow, value::SerializeValue},
    transport::errors::QueryError,
    QueryResult, Session,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::{event, Level};
use validator::{ValidateEmail, ValidateLength};
use zxcvbn::Score;

// TODO: Add rate limit.
// TODO: Log login.
// TODO: Add risk-based security.
// TODO: Add MFA.
// TODO: Add rules checks.
pub async fn sign_up(
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    Extension(RequestID(request_id)): Extension<RequestID>,
    Extension(response_meta): Extension<ResponseMeta<'_>>,
    State(state): State<AppState>,
    payload: Result<Json<Request<SignUpPayload>>, JsonRejection>,
) -> response::Response<Body> {
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
        let response: Response<Value> =
            Response::new(None, Some(errors), Some(response_meta), None);

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
            Some(response_meta),
            Some(HashMap::from([("verify", "/auth/sign-up/verify")])),
        ),
    )
        .into_response()
}

// TODO: Add rate limit.
pub async fn sign_in(
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    Extension(RequestID(request_id)): Extension<RequestID>,
    Extension(response_meta): Extension<HashMap<&str, Value>>,
    State(state): State<AppState>,
    payload: Result<Json<Request<SignInPayload>>, JsonRejection>,
) -> response::Response<Body> {
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

    let state = state.read().await;

    async fn query_user(
        db: &Session,
        tenant_id: &String,
        request_id: &String,
        login: impl SerializeValue,
        table: &str,
        id_column: &str,
        query_column: &str,
        internal_error_code: usize,
    ) -> Result<Option<String>, CommonError> {
        let result = db
            .query_unpaged(
                format!(
                    "SELECT {id_column} FROM {table} WHERE tenant_id = ? AND {query_column} = ?"
                ),
                (&tenant_id, login),
            )
            .await;

        if let Err(e) = result {
            event!(Level::ERROR, error = format!("{e}"));

            return Err(CommonError::InternalServerError {
                internal_code: internal_error_code,
                request_id: request_id.to_owned(),
                tenant_id: Some(tenant_id.to_owned()),
            });
        }

        let result = result.unwrap();

        if let Some(rows) = &result.rows {
            if rows.len() != 0 {
                return Ok(Some(
                    result
                        .first_row_typed::<(String,)>()
                        .expect("The query was expected to be able to return rows.")
                        .0,
                ));
            }
        }

        Ok(None)
    }

    let mut user_id: Option<String> = None;

    if payload.login.validate_email() {
        user_id = match query_user(
            &state.db,
            &tenant_id,
            &request_id,
            &payload.login,
            "users_by_email",
            "user_id",
            "email",
            8,
        )
        .await
        {
            Err(e) => return e.into_response(),
            Ok(id) => id,
        }
    }

    if user_id == None {
        user_id = match query_user(
            &state.db,
            &tenant_id,
            &request_id,
            &payload.login,
            "users_by_username",
            "id",
            "username",
            9,
        )
        .await
        {
            Err(e) => return e.into_response(),
            Ok(id) => id,
        }
    }

    if user_id == None {
        user_id = match query_user(
            &state.db,
            &tenant_id,
            &request_id,
            &payload.login,
            "users_by_phone_number",
            "user_id",
            "number",
            10,
        )
        .await
        {
            Err(e) => return e.into_response(),
            Ok(id) => id,
        }
    }

    let invalid_credentials_response = error_response(
        StatusCode::UNAUTHORIZED,
        "Invalid Credentials",
        "The credentials provided were invalid.",
        Some("body.data"),
        HashMap::from([
            ("login", json!(payload.login)),
            ("password", json!(payload.password)),
        ]),
        request_id.clone(),
        Some(tenant_id.clone()),
    )
    .into_response();

    match user_id {
        None => return invalid_credentials_response,
        Some(id) => {
            let user_result = state
                .db
                .query_unpaged(
                    "SELECT password FROM users WHERE tenant_id = ? AND id = ?",
                    (&tenant_id, &id),
                )
                .await;

            if let Err(e) = user_result {
                event!(Level::ERROR, error = format!("{e}"));

                return CommonError::InternalServerError {
                    internal_code: 11,
                    request_id,
                    tenant_id: Some(tenant_id),
                }
                .into_response();
            }

            let password_hash = user_result.unwrap().first_row_typed::<(String,)>();

            match password_hash {
                Err(e) => {
                    event!(Level::ERROR, error = format!("{e}"));

                    return CommonError::InternalServerError {
                        internal_code: 12,
                        request_id,
                        tenant_id: Some(tenant_id),
                    }
                    .into_response();
                }
                Ok((hash,)) => match bcrypt::verify(payload.password, &hash) {
                    Err(e) => {
                        event!(Level::ERROR, error = format!("{e}"));

                        return CommonError::InternalServerError {
                            internal_code: 13,
                            request_id,
                            tenant_id: Some(tenant_id),
                        }
                        .into_response();
                    }
                    Ok(is_valid) => {
                        if !is_valid {
                            return invalid_credentials_response;
                        }
                    }
                },
            }

            let access_token = token(None);
            let refresh_token = token(None);

            let mut batch = Batch::default();

            // TODO: Make the expiry times configurable by tenant.

            batch.append_statement("INSERT INTO api_tokens (tenant_id, user_id, api_token, type, scopes, created_at) VALUES (?, ?, ?, 0, {}, toTimestamp(now())) USING TTL 3600");
            batch.append_statement("INSERT INTO api_tokens (tenant_id, user_id, api_token, type, scopes, created_at) VALUES (?, ?, ?, 1, {}, toTimestamp(now())) USING TTL 2628288"); // A month.

            let batch_result = state
                .db
                .batch(
                    &batch,
                    (
                        (&tenant_id, &id, &access_token),
                        (&tenant_id, &id, &refresh_token),
                    ),
                )
                .await;

            match batch_result {
                Err(e) => {
                    event!(Level::ERROR, error = format!("{e}"));
                    return CommonError::InternalServerError {
                        internal_code: 14,
                        request_id,
                        tenant_id: Some(tenant_id),
                    }
                    .into_response();
                }
                Ok(_) => {
                    return Json(Response::new(
                        Some(SignInResponse {
                            user_id: id,
                            access_token: URL_SAFE.encode(access_token),
                            refresh_token: URL_SAFE.encode(refresh_token),
                            access_token_expires_in: 3600,
                            refresh_token_expires_in: 2_628_288,
                            scopes: vec!["all".to_string()],
                        }),
                        None,
                        Some(response_meta),
                        Some(HashMap::from([
                            ("self", "/users/@me"),
                            ("token", "/auth/token"),
                        ])),
                    ))
                    .into_response()
                }
            }
        }
    }
}
