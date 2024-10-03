use hmac::Hmac;
use redis_pool::SingleRedisPool;
use scylla::Session;
use sha2::Sha384;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct State {
    pub db: Session,
    pub redis: SingleRedisPool,
    pub hmac: Hmac<Sha384>,
}

pub type AppState = Arc<RwLock<State>>;
