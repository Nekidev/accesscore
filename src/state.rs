use std::sync::Arc;

use redis_pool::SingleRedisPool;
use scylla::Session;
use tokio::sync::Mutex;

pub struct State {
    pub db: Session,
    pub redis: SingleRedisPool,
}

pub type AppState = Arc<Mutex<State>>;
