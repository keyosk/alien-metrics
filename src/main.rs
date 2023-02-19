use alien_metrics::{AlienClient, AlienError, Metrics};
use axum::{extract::State, http::StatusCode, routing::get, Router, Server};
use prometheus::TextEncoder;

use std::sync::Arc;

async fn serve_req(State(metrics): State<Arc<Metrics>>) -> (StatusCode, String) {
    let encoder = TextEncoder::new();

    metrics.http_counter.inc();

    let metric_families = prometheus::gather();
    match encoder.encode_to_string(&metric_families) {
        Ok(body) => (StatusCode::OK, body),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

async fn main_loop(metrics: Arc<Metrics>) -> Result<(), AlienError> {
    let one_sec = tokio::time::Duration::from_secs(1);
    let sleep_interval = tokio::time::Duration::from_secs(15);

    let mut alien_client = AlienClient::new().await?;

    loop {
        metrics.scrape_counter.inc();

        let values = alien_client.get_metrics().await;

        if let Ok(values) = values {
            alien_client.record_metrics(&metrics, values)?;
            tokio::time::sleep(sleep_interval).await
        } else {
            println!("DEBUG: Session expired. Logging in again");
            alien_client.login().await?;
            alien_client.capture_metrics_token().await?;
            tokio::time::sleep(one_sec).await
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), AlienError> {
    let metrics = Arc::new(Metrics::new()?);
    let addr = "0.0.0.0:9898".parse().unwrap();
    println!("Listening on http://{}", addr);

    let app = Router::new()
        .route("/metrics", get(serve_req))
        .with_state(metrics.clone());
    let serve_future = Server::bind(&addr).serve(app.into_make_service());

    tokio::select! {
        _ = serve_future => {
            eprintln!("ERROR: Metrics endpoint serve failure")
        },
        _ = main_loop(metrics) => {
            eprintln!("ERROR: Login or Parse error, double check credentials and connectivity")
        },
    }

    Ok(())
}
