use axum::{
    extract::{rejection::JsonRejection, State},
    http::StatusCode,
    Extension, Json,
};
use serde_json::Value;

use crate::{
    requests::Request,
    responses::{CommonError, Response},
    state::AppState,
    types::TenantID,
};

use super::requests::SignUpPayload;

pub async fn sign_up(
    Extension(TenantID(tenant_id)): Extension<TenantID>,
    State(state): State<AppState>,
    payload: Result<Json<Request<SignUpPayload>>, JsonRejection>,
) -> Result<(StatusCode, Json<Response<Value>>), CommonError> {
    let payload = payload.map_err(CommonError::from)?;

    todo!();
}
