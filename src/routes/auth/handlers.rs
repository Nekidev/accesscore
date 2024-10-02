use axum::{extract::State, Extension};

use crate::{state::AppState, types::TenantID};

pub async fn sign_up(
    Extension(TenantID { id: tenant_id }): Extension<TenantID>,
    State(state): State<AppState>
) {

}
