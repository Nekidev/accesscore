use scylla::{frame::Compression, Session, SessionBuilder};
use std::{env, time::Duration};

pub async fn session() -> Session {
    let hosts: String =
        env::var("SCYLLA_HOSTS").unwrap_or("scylla-main,scylla-1,scylla-2".to_string());
    let hosts_vec: Vec<&str> = hosts.split(',').collect();

    let mut builder = SessionBuilder::new();

    for host in hosts_vec {
        builder = builder.known_node(host);
    }

    builder
        .connection_timeout(Duration::from_secs(3))
        .compression(Some(Compression::Lz4))
        .build()
        .await
        .unwrap()
}

pub async fn init(session: &Session) {
    let _ = session.query_unpaged("
        CREATE KEYSPACE 
    ", ()).await;
}
