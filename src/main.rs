use alien_metrics::{AlienClient, AlienError, Metrics};
use axum::{extract::State, http::StatusCode, routing::get, Router, Server};
use prometheus::TextEncoder;
use std::sync::Arc;
use tokio::{
    select,
    signal::{
        ctrl_c,
        unix::{signal, SignalKind},
    },
    time::{sleep, Duration},
};
use tracing::{error, info};

async fn main_loop(metrics: Arc<Metrics>) -> Result<(), AlienError> {
    let one_sec = Duration::from_secs(1);
    let sleep_interval = Duration::from_secs(15);

    let mut alien_client = AlienClient::new().await?;

    loop {
        metrics.scrape_counter.inc();

        let device_info = alien_client.get_info().await;

        if let Ok(device_info) = device_info {
            alien_client.record_metrics(&metrics, device_info)?;
            sleep(sleep_interval).await
        } else {
            alien_client.re_login().await?;
            sleep(one_sec).await
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
        ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal(SignalKind::terminate())
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
    let addr = "0.0.0.0:9898".parse().unwrap();
    info!("Listening on http://{}/metrics", addr);

    let app = Router::new()
        .route("/metrics", get(serve_req))
        .with_state(metrics.clone());
    let serve_future = Server::bind(&addr)
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal());

    select! {
        res = serve_future => {
            if res.is_err() {
                error!("Metrics endpoint serve failure: {:?}", res);
            }
        },
        res = main_loop(metrics) => {
            if res.is_err() {
                error!("Login or Parse error, double check credentials and connectivity: {:?}", res);
            }
        },
    }
}
