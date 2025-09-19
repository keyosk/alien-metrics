// Testing GHA cache

use alien_metrics::{AlienClient, AlienError, Metrics};
use axum::{extract::State, http::StatusCode, routing::get, Router};
use prometheus::TextEncoder;
use std::{future::IntoFuture, sync::Arc};
use tokio::{
    net::TcpListener,
    select, signal,
    time::{sleep, Duration},
};
use tracing::{error, info};

async fn main_loop(metrics: Arc<Metrics>) -> Result<(), AlienError> {
    let one_sec = Duration::from_secs(1);
    let sleep_interval = Duration::from_secs(15);

    let mut alien_client = AlienClient::new().await?;

    loop {
        match alien_client.get_info().await {
            Ok(device_info) => {
                metrics.scrape_counter.inc();
                // TODO: capture subsequent error here as a metric and keep spinning the loop
                alien_client.record_metrics(&metrics, device_info)?;
                sleep(sleep_interval).await
            }
            Err(e) => {
                metrics.scrape_error_counter.inc();
                error!("Unable to retrieve info from alien: {:?}", e);
                if let Err(e) = alien_client.re_login().await {
                    // TODO: capture metric
                    error!("Subsequent login failure: {:?}", e);
                }
                sleep(one_sec).await
            }
        }
    }
}

async fn serve_req(State(metrics): State<Arc<Metrics>>) -> (StatusCode, String) {
    let encoder = TextEncoder::new();

    metrics.http_counter.inc();

    let metric_families = prometheus::gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(body) => (StatusCode::OK, body),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal received, starting graceful shutdown");
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let metrics = Arc::new(Metrics::new().unwrap());
    let addr = "0.0.0.0:9898";
    info!("Attempting to listen on http://{}/metrics", addr);
    match TcpListener::bind(&addr).await {
        Ok(listener) => {
            let app = Router::new()
                .route("/metrics", get(serve_req))
                .with_state(metrics.clone());
            let serve_future = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown_signal())
                .into_future();
            info!("Listening on http://{}/metrics", addr);
            select! {
                res = serve_future => {
                    if let Err(e) = res {
                        error!("Metrics endpoint serve failure: {:?}", e);
                    }
                },
                res = main_loop(metrics) => {
                    if let Err(e) = res {
                        error!("Login or Parse error, double check credentials and connectivity: {:?}", e);
                    }
                },
            }
        }
        Err(e) => {
            error!("Unable to bind metrics port: {:?}", e)
        }
    }
}
