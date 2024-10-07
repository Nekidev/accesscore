// pub mod orm;

use scylla::{
    frame::Compression,
    transport::downgrading_consistency_retry_policy::DowngradingConsistencyRetryPolicy,
    ExecutionProfile, Session, SessionBuilder,
};
use std::{env, fs, time::Duration};

pub async fn session() -> Session {
    let hosts: String =
        env::var("SCYLLA_HOSTS").unwrap_or("scylla-main,scylla-1,scylla-2".to_string());
    let hosts_vec: Vec<&str> = hosts.split(',').collect();

    let mut builder = SessionBuilder::new();

    for host in hosts_vec {
        builder = builder.known_node(host);
    }

    let execution_profile_handle = ExecutionProfile::builder()
        .retry_policy(Box::new(DowngradingConsistencyRetryPolicy::new()))
        .request_timeout(Some(Duration::from_secs(2)))
        .build()
        .into_handle();

    builder
        .connection_timeout(Duration::from_secs(3))
        .compression(Some(Compression::Lz4))
        .default_execution_profile_handle(execution_profile_handle)
        .build()
        .await
        .expect("ScyllaDB pool had no connections, meaning no known node is up. Check for their availability and try again.")
}

pub async fn init(session: &Session) {
    let init_query =
        fs::read_to_string("cql/init.cql").expect("Should have been able to read cql/init.cql.");

    let queries: Vec<&str> = init_query.split(";").collect();

    for mut query in queries {
        query = query.trim();

        if query.trim() == "" {
            continue;
        }

        match session.query_unpaged(query, ()).await {
            Err(err) => {
                panic!("\n{err:?}:\n\n{query}\n");
            }
            _ => {}
        };
    }
}
