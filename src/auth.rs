#[derive(Debug, Clone)]
pub struct Auth {
    pub user_id: Option<String>,
    pub token: Option<String>,
    pub scopes: Vec<String>,
    pub client_id: Option<String>,
}
