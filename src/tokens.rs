use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Flow,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flow {
    SignUpEmailVerification,
}

#[derive(Serialize, Deserialize)]
pub struct FlowToken {
    pub token_type: TokenType,
    pub flow: Flow,
    pub tenant_id: String,
    pub user_id: String,
    pub expires_at: i64,
}

/// Generates a cryptographically secure random token of `size` bytes long, which defaults to 64
/// for a 64 character long token.
pub fn token(size: Option<usize>) -> Vec<u8> {
    let mut data = vec![0u8; size.unwrap_or(64)];
    OsRng.fill_bytes(&mut data);
    data
}
