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
