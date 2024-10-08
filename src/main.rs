use accesscore::db;
use accesscore::error_handlers::handler_404;
use accesscore::middleware as ac_middleware;
use accesscore::redis;
use accesscore::state::State;
use accesscore::{routes, state::AppState};
use axum::middleware as ax_middleware;
use axum::Router;
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha384;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tower_http::{
    compression::CompressionLayer, decompression::DecompressionLayer, limit::RequestBodyLimitLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
};
use tracing::event;
use tracing::Level;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let debug: bool = env::var("DEBUG").unwrap_or("true".to_string()) == "true".to_string();

    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    if debug {
        dotenv::from_filename("dev.env").ok();
    }

    event!(Level::INFO, "Connecting to ScyllaDB node...");
    let scylla_session = db::session().await;
    event!(
        Level::INFO,
        "Connected to ScyllaDB node. Running initial query..."
    );
    db::init(&scylla_session).await;
    event!(Level::INFO, "Initial query ran.");

    event!(Level::INFO, "Connecting to Redis...");
    let redis_session = redis::session().await;
    event!(Level::INFO, "Connected to Redis.");

    let key: Hmac<Sha384> = Hmac::new_from_slice(b"uwu nya").unwrap();

    let state: AppState = Arc::new(RwLock::new(State {
        db: scylla_session,
        redis: redis_session,
        hmac: key,
    }));

    let app = Router::new()
        .nest("/auth", routes::auth::router())
        .nest("/users", routes::users::router())
        .fallback(handler_404)
        .layer(
            // Keep above request_id(), response_meta(), and tenant() middleware.
            ax_middleware::from_fn_with_state(state.clone(), ac_middleware::authentication),
        )
        .layer(ax_middleware::from_fn_with_state(
            // Keep above tenant and request_id middlewares.
            state.clone(),
            ac_middleware::response_meta,
        ))
        .layer(ax_middleware::from_fn_with_state(
            // Keep as first DB-linked middleware.
            state.clone(),
            ac_middleware::tenant,
        ))
        .layer(ax_middleware::from_fn_with_state(
            // Keep above all the DB-linked middleware to prevent useless calls to the DB.
            state.clone(),
            ac_middleware::global_ratelimit,
        ))
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
        .layer(ax_middleware::from_fn_with_state(
            state.clone(),
            ac_middleware::request_id,
        ))
        .with_state(state);

    event!(Level::INFO, "Starting server...");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
