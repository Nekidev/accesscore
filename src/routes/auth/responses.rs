use serde::Serialize;

#[derive(Serialize)]
pub struct TokenResponse {
    pub user_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_in: u64,
    pub refresh_token_expires_in: u64,
    pub scopes: Vec<String>,
    pub token_type: String,
}
