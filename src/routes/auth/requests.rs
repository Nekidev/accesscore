use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SignUpPayload {
    pub email: String,
    pub phone_number: Option<String>,
    pub username: Option<String>,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SignInPayload {
    pub login: String,
    pub password: String
}
