use std::env;

use redis_pool::{RedisPool, SingleRedisPool};

pub async fn session() -> SingleRedisPool {
    let url = env::var("REDIS_URL").unwrap_or("redis://redis/".to_string());
    let client = redis::Client::open(url).unwrap();
    RedisPool::from(client)
}
