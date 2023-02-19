use async_trait::async_trait;
use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use once_cell::sync::Lazy;
use prometheus::{
    labels, opts, register_counter, register_gauge_vec, Counter, Encoder, GaugeVec, TextEncoder,
};
use reqwest::{cookie::Jar, Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufRead, BufReader, Write},
};
use thiserror::Error;

static LOGIN_PASSWORD: Lazy<String> =
    Lazy::new(|| env::var("ROUTER_PASSWORD").expect("env ROUTER_PASSWORD"));
static BRIDGE_IP: Lazy<String> = Lazy::new(|| env::var("BRIDGE_IP").expect("env BRIDGE_IP"));

static HTTP_COUNTER: Lazy<Counter> = Lazy::new(|| {
    register_counter!(opts!(
        "http_requests_total",
        "Number of HTTP requests made.",
        labels! {"handler" => "all",}
    ))
    .expect("UNABLE TO REGISTER METRIC")
});

static SCRAPE_COUNTER: Lazy<Counter> = Lazy::new(|| {
    register_counter!(opts!(
        "scrape_requests_total",
        "Number of times scraped alien metrics endpoint.",
    ))
    .expect("UNABLE TO REGISTER METRIC")
});

static DEVICE_HAPPINESS_GAUGE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "device_happiness",
        "The Happiness score of each device.",
        &["mac", "name"]
    )
    .expect("UNABLE TO REGISTER METRIC")
});

static DEVICE_SIGNAL_GAUGE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "device_signal",
        "The Signal score of each device.",
        &["mac", "name"]
    )
    .expect("UNABLE TO REGISTER METRIC")
});

static DEVICE_RX_BITRATE_GAUGE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "device_rx_bitrate",
        "The rx bitrate of each device.",
        &["mac", "name"]
    )
    .expect("UNABLE TO REGISTER METRIC")
});

static DEVICE_TX_BITRATE_GAUGE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "device_tx_bitrate",
        "The tx bitrate of each device.",
        &["mac", "name"]
    )
    .expect("UNABLE TO REGISTER METRIC")
});

static DEVICE_RX_BYTES_GAUGE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "device_rx_bytes",
        "The rx bytes of each device.",
        &["mac", "name"]
    )
    .expect("UNABLE TO REGISTER METRIC")
});

static DEVICE_TX_BYTES_GAUGE: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "device_tx_bytes",
        "The tx bytes of each device.",
        &["mac", "name"]
    )
    .expect("UNABLE TO REGISTER METRIC")
});

#[derive(Error, Debug)]
pub enum AlienError {
    #[error("reqwest error")]
    ReqwestError(#[from] reqwest::Error),
    #[error("token cache r/w error")]
    TokenCacheError(#[from] std::io::Error),
    #[error("env BRIDGE_IP error")]
    BridgeIPError(#[from] url::ParseError),
    #[error("login error")]
    CookieError(#[from] reqwest::header::ToStrError),
    #[error("metrics token missing error")]
    MetricsTokenMissingError,
    #[error("invalid password error")]
    InvalidPasswordError(String),
    #[error("login token missing error")]
    LoginTokenMissingError(String),
    #[error("devices list parse error")]
    DevicesParseError,
    #[error("metrics parse error")]
    MetricsParseError(#[from] serde_json::Error),
    #[error("server error")]
    ServerError(#[from] hyper::Error),
    #[error("server 2 error")]
    Server2Error(#[from] hyper::http::Error),
    #[error("server 3 error")]
    Server3Error(#[from] prometheus::Error),
    #[error("unknown error")]
    Unknown,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Device {
    pub address: String,
    pub description: String,
    pub happiness_score: f64,
    pub host_name: String,
    pub inactive: f64,
    pub lease_validity: f64,
    pub max_bandwidth: f64,
    pub max_spatial_streams: f64,
    pub mode: String,
    pub radio_mode: String,
    pub rx_bitrate: f64,
    pub rx_bytes: f64,
    #[serde(rename = "RxBytes_5sec")]
    pub rx_bytes_5sec: f64,
    #[serde(rename = "RxBytes_15sec")]
    pub rx_bytes_15sec: f64,
    #[serde(rename = "RxBytes_30sec")]
    pub rx_bytes_30sec: f64,
    #[serde(rename = "RxBytes_60sec")]
    pub rx_bytes_60sec: f64,
    pub rx_mcs: f64,
    pub rx_mhz: f64,
    pub signal_quality: f64,
    pub tx_bitrate: f64,
    pub tx_bytes: f64,
    #[serde(rename = "TxBytes_5sec")]
    pub tx_bytes_5sec: f64,
    #[serde(rename = "TxBytes_15sec")]
    pub tx_bytes_15sec: f64,
    #[serde(rename = "TxBytes_30sec")]
    pub tx_bytes_30sec: f64,
    #[serde(rename = "TxBytes_60sec")]
    pub tx_bytes_60sec: f64,
    pub tx_mcs: f64,
    pub tx_mhz: f64,
}

pub trait DeviceInfo {
    fn get_name(&self) -> &str;
}

impl DeviceInfo for Device {
    fn get_name(&self) -> &str {
        if !self.description.is_empty() {
            &self.description
        } else if !self.host_name.is_empty() {
            &self.host_name
        } else {
            &self.address
        }
    }
}

type AlienMetricsRoot = Vec<HashMap<String, Value>>;
type AlienMetrics = HashMap<String, HashMap<String, HashMap<String, Device>>>;

#[derive(Default, Debug, Clone)]
pub struct AlienClient {
    client: Client,
    session_cookie: String,
    metrics_token: String,
}

#[async_trait]
pub trait AlienClientMethods {
    async fn init(&mut self) -> Result<(), AlienError>;
    async fn get_login_token(&self) -> Result<String, AlienError>;
    async fn capture_metrics_token(&mut self) -> Result<(), AlienError>;
    async fn login(&mut self) -> Result<(), AlienError>;
    async fn get_metrics(&self) -> Result<AlienMetricsRoot, AlienError>;
    fn get_client_with_old_cookie(&mut self) -> Result<Client, AlienError>;
    fn record_metrics(&self, res: AlienMetricsRoot) -> Result<(), AlienError>;
}

#[async_trait]
impl AlienClientMethods for AlienClient {
    fn get_client_with_old_cookie(&mut self) -> Result<Client, AlienError> {
        let path = "cookie.txt";

        let input = File::open(path)?;
        let buffered = BufReader::new(input);

        let jar = Jar::default();

        if let Some(line) = buffered.lines().next() {
            self.session_cookie = line?;
        }

        let url = format!("http://{BRIDGE_IP}", BRIDGE_IP = &BRIDGE_IP.as_str()).parse::<Url>()?;
        jar.add_cookie_str(&self.session_cookie, &url);

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .cookie_provider(jar.into())
            .build()?;

        Ok(client)
    }

    async fn get_login_token(&self) -> Result<String, AlienError> {
        // Step 1: Get login token

        let login_token_response = self
            .client
            .get(format!(
                "http://{BRIDGE_IP}/login.php",
                BRIDGE_IP = &BRIDGE_IP.as_str()
            ))
            .send()
            .await?
            .text()
            .await?;

        // println!("_BB: {:?}", &login_token_response);

        Ok(
            find_pattern(&login_token_response, r#"name='token' value='"#, r#"'"#)
                .ok_or(AlienError::LoginTokenMissingError(
                    login_token_response.clone(),
                ))?
                .to_string(),
        )
    }

    async fn login(&mut self) -> Result<(), AlienError> {
        // Step 2: Login and get session cookie

        self.client = reqwest::Client::builder().cookie_store(true).build()?;

        let login_params = [
            ("token", &self.get_login_token().await?),
            ("password", &LOGIN_PASSWORD),
        ];

        let res = self
            .client
            .post(format!(
                "http://{BRIDGE_IP}/login.php",
                BRIDGE_IP = &BRIDGE_IP.as_str()
            ))
            .form(&login_params)
            .send()
            .await?;

        self.session_cookie = res
            .headers()
            .get("set-cookie")
            .ok_or(AlienError::InvalidPasswordError(String::from(
                "No cookie returned",
            )))?
            .to_str()?
            .to_string();

        let path = "cookie.txt";
        let mut output = File::create(path)?;

        write!(output, "{}", &self.session_cookie)?;

        let res_text = res.text().await?;

        if res_text.contains("URL='info.php'")
            || res_text.contains("URL='index.php'")
            || res_text.contains("URL='settings.php'")
        {
            Ok(())
        } else if res_text.contains("URL='login.php'") {
            Err(AlienError::InvalidPasswordError(String::from(
                "Invalid password",
            )))
        } else {
            Err(AlienError::InvalidPasswordError(String::from(
                "Unexpected response",
            )))
        }
    }

    async fn capture_metrics_token(&mut self) -> Result<(), AlienError> {
        // Step 3: Get the metrics token

        let metrics_token_response = self
            .client
            .get(format!(
                "http://{BRIDGE_IP}/info.php",
                BRIDGE_IP = BRIDGE_IP.as_str()
            ))
            .send()
            .await?
            .text()
            .await?;

        self.metrics_token = find_pattern(&metrics_token_response, r#"var token='"#, r#"'"#)
            .ok_or(AlienError::MetricsTokenMissingError)?
            .to_string();
        Ok(())
    }

    async fn get_metrics(&self) -> Result<AlienMetricsRoot, AlienError> {
        // Step 4: pull metrics json

        let metrics_params = [("do", "full"), ("token", &self.metrics_token)];

        let res = &self
            .client
            .post(format!(
                "http://{BRIDGE_IP}/info-async.php",
                BRIDGE_IP = BRIDGE_IP.as_str()
            ))
            .form(&metrics_params)
            .send()
            .await?
            .json::<AlienMetricsRoot>()
            .await?;

        Ok(res.to_vec())
    }

    fn record_metrics(&self, res: AlienMetricsRoot) -> Result<(), AlienError> {
        for frequencies in res.get(1).ok_or(AlienError::DevicesParseError)?.values() {
            for networks in serde_json::from_value::<AlienMetrics>(frequencies.to_owned())?.values()
            {
                for devices in networks.values() {
                    for (device_mac, device) in devices {
                        DEVICE_HAPPINESS_GAUGE
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.happiness_score);
                        DEVICE_SIGNAL_GAUGE
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.signal_quality);
                        DEVICE_RX_BITRATE_GAUGE
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.rx_bitrate);
                        DEVICE_TX_BITRATE_GAUGE
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.tx_bitrate);
                        DEVICE_RX_BYTES_GAUGE
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.rx_bytes);
                        DEVICE_TX_BYTES_GAUGE
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.tx_bytes);
                    }
                }
            }
        }
        Ok(())
    }

    async fn init(&mut self) -> Result<(), AlienError> {
        self.client = {
            if let Ok(client) = self.get_client_with_old_cookie() {
                client
            } else {
                reqwest::Client::builder().cookie_store(true).build()?
            }
        };
        if self.session_cookie.is_empty() {
            println!("Empty session token.... logging in...");
            self.login().await?;
        }
        if self.capture_metrics_token().await.is_err() {
            // It's possible the cached session cookie is no longer valid
            // If the next login and capture fails, bail out with error
            self.login().await?;
            self.capture_metrics_token().await?;
        }
        Ok(())
    }
}

fn find_pattern<'a>(input: &'a str, open: &str, close: &str) -> Option<&'a str> {
    match input.find(open) {
        Some(index) => {
            let start = index + open.len();
            match input[start..].find(close) {
                Some(index) if index > 0 => Some(&input[start..start + index]),
                _ => None,
            }
        }
        None => None,
    }
}

async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, AlienError> {
    let encoder = TextEncoder::new();

    HTTP_COUNTER.inc();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer)?;

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))?;

    Ok(response)
}

async fn main_loop() -> Result<(), AlienError> {
    let one_sec = tokio::time::Duration::from_secs(1);
    let sleep_interval = tokio::time::Duration::from_secs(15);

    let mut alien_client = AlienClient {
        ..Default::default()
    };

    alien_client.init().await?;

    loop {
        SCRAPE_COUNTER.inc();

        let metrics = alien_client.get_metrics().await;

        if let Ok(metrics) = metrics {
            alien_client.record_metrics(metrics)?;
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
    let addr = ([0, 0, 0, 0], 9898).into();
    println!("Listening on http://{}", addr);

    let serve_future = Server::bind(&addr).serve(make_service_fn(|_| async {
        Ok::<_, AlienError>(service_fn(serve_req))
    }));

    tokio::select! {
        _ = serve_future => {
            eprintln!("ERROR: Metrics endpoint serve failure")
        },
        _ = main_loop() => {
            eprintln!("ERROR: Login or Parse error, double check credentials and connectivity")
        },
    }

    Ok(())
}
