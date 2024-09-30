use accesscore::db;
use accesscore::redis;
use accesscore::routes::handler_404;
use accesscore::state::State;
use accesscore::{routes, state::AppState};
use axum::Router;
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tower_http::{
    compression::CompressionLayer, decompression::DecompressionLayer, limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
};

#[tokio::main]
async fn main() {
    let debug: bool = env::var("DEBUG").unwrap_or("true".to_string()) == "true".to_string();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    if debug {
        dotenv::from_filename("dev.env").ok();
    }

    let scylla_session = db::session().await;

    let redis_session = redis::session().await;

    let state: AppState = Arc::new(Mutex::new(State {
        db: scylla_session,
        redis: redis_session,
    }));

    let app = Router::new()
        .merge(routes::auth::router())
        .fallback(handler_404)
        .layer(TraceLayer::new_for_http())
        .layer(
            CompressionLayer::new()
                .br(true)
                .gzip(true)
                .deflate(true)
                .zstd(true),
        )
        .layer(
            DecompressionLayer::new()
                .br(true)
                .gzip(true)
                .deflate(true)
                .zstd(true),
        )
        .layer(RequestBodyLimitLayer::new(8192))
        .layer(TimeoutLayer::new(Duration::from_secs(2)))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .unwrap();
}

async fn shutdown() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
