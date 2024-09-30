use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Request<T> {
    pub data: T,
    pub flow_token: Option<String>,
}
