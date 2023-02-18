use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Request, Response, Server,
};
use prometheus::{Counter, Encoder, Gauge, GaugeVec, HistogramVec, TextEncoder};

use lazy_static::lazy_static;
use prometheus::{
    labels, opts, register_counter, register_gauge, register_gauge_vec, register_histogram_vec,
};

use once_cell::sync::Lazy;
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
static BRIDGE_IP: Lazy<String> =
    Lazy::new(|| env::var("BRIDGE_IP").unwrap_or(String::from("192.168.188.1")));

lazy_static! {
    static ref HTTP_COUNTER: Counter = register_counter!(opts!(
        "example_http_requests_total",
        "Number of HTTP requests made.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    static ref HTTP_BODY_GAUGE: Gauge = register_gauge!(opts!(
        "example_http_response_size_bytes",
        "The HTTP response sizes in bytes.",
        labels! {"handler" => "all",}
    ))
    .unwrap();
    static ref HTTP_REQ_HISTOGRAM: HistogramVec = register_histogram_vec!(
        "example_http_request_duration_seconds",
        "The HTTP request latencies in seconds.",
        &["handler"]
    )
    .unwrap();
    static ref DEVICE_HAPPINESS: GaugeVec = register_gauge_vec!(
        "device_happiness",
        "The Happiness score of each device.",
        &["mac", "name"]
    )
    .unwrap();
}

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
pub struct RouterInfo {
    pub cost: i64,
    pub friendly_name: String,
    pub ip: String,
    pub level: i64,
    pub mac: String,
    pub platform_name: String,
    pub protocol: i64,
    pub region_lock: String,
    pub role: String,
    pub uptime: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
pub struct Device {
    pub address: String,
    pub description: String,
    pub happiness_score: u64,
    pub host_name: String,
    pub inactive: u64,
    pub lease_validity: u64,
    pub max_bandwidth: u64,
    pub max_spatial_streams: u64,
    pub mode: String,
    pub radio_mode: String,
    pub rx_bitrate: u64,
    pub rx_bytes: u64,
    #[serde(rename = "RxBytes_5sec")]
    pub rx_bytes_5sec: u64,
    #[serde(rename = "RxBytes_15sec")]
    pub rx_bytes_15sec: u64,
    #[serde(rename = "RxBytes_30sec")]
    pub rx_bytes_30sec: u64,
    #[serde(rename = "RxBytes_60sec")]
    pub rx_bytes_60sec: u64,
    pub rx_mcs: u64,
    pub rx_mhz: u64,
    pub signal_quality: u64,
    pub tx_bitrate: u64,
    pub tx_bytes: u64,
    #[serde(rename = "TxBytes_5sec")]
    pub tx_bytes_5sec: u64,
    #[serde(rename = "TxBytes_15sec")]
    pub tx_bytes_15sec: u64,
    #[serde(rename = "TxBytes_30sec")]
    pub tx_bytes_30sec: u64,
    #[serde(rename = "TxBytes_60sec")]
    pub tx_bytes_60sec: u64,
    pub tx_mcs: u64,
    pub tx_mhz: u64,
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

async fn login(client: &Client) -> Result<(), AlienError> {
    // Step 1: Get login token

    let login_token_response = client
        .get(format!(
            "http://{BRIDGE_IP}/login.php",
            BRIDGE_IP = &BRIDGE_IP.as_str()
        ))
        .send()
        .await?
        .text()
        .await?;

    let login_token = find_pattern(&login_token_response, r#"name='token' value='"#, r#"'"#)
        .ok_or(AlienError::LoginTokenMissingError(
            login_token_response.clone(),
        ))?;

    // Step 2: Login and get session cookie

    let login_params = [("token", login_token), ("password", &LOGIN_PASSWORD)];

    let res = client
        .post(format!(
            "http://{BRIDGE_IP}/login.php",
            BRIDGE_IP = &BRIDGE_IP.as_str()
        ))
        .form(&login_params)
        .send()
        .await?;

    let login_cookie = res
        .headers()
        .get("set-cookie")
        .ok_or(AlienError::InvalidPasswordError(String::from(
            "No cookie returned",
        )))?;

    let path = "cookie.txt";
    let mut output = File::create(path)?;

    write!(output, "{}", login_cookie.to_str()?)?;

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

async fn get_metrics_token(client: &Client) -> Result<String, AlienError> {
    // Step 3: Get the metrics token

    let metrics_token_response = client
        .get(format!(
            "http://{BRIDGE_IP}/info.php",
            BRIDGE_IP = BRIDGE_IP.as_str()
        ))
        .send()
        .await?
        .text()
        .await?;

    let metrics_token = find_pattern(&metrics_token_response, r#"var token='"#, r#"'"#)
        .ok_or(AlienError::MetricsTokenMissingError)?;

    Ok(String::from(metrics_token))
}

async fn get_metrics(
    client: &Client,
    metrics_token: &str,
) -> Result<Vec<HashMap<String, Value>>, AlienError> {
    // Step 4: pull metrics json

    let metrics_params = [("do", "full"), ("token", metrics_token)];

    let res = client
        .post(format!(
            "http://{BRIDGE_IP}/info-async.php",
            BRIDGE_IP = BRIDGE_IP.as_str()
        ))
        .form(&metrics_params)
        .send()
        .await?
        .json::<Vec<HashMap<String, Value>>>()
        .await?;

    Ok(res)
}

fn print_metrics(res: Vec<HashMap<String, Value>>) -> Result<(), AlienError> {
    let mut res_array = res.iter();

    // remove first item from res_array, it's the router info
    let ri: RouterInfo = serde_json::from_value(
        res_array
            .next()
            .ok_or(AlienError::DevicesParseError)?
            .values()
            .next()
            .ok_or(AlienError::DevicesParseError)?
            .to_owned(),
    )?;

    println!("router_info: {:?}", ri);

    // remove the second item from res_array, it's a complex map of devices
    let frequencies: HashMap<String, HashMap<String, HashMap<String, Device>>> =
        serde_json::from_value(
            res_array
                .next()
                .ok_or(AlienError::DevicesParseError)?
                .get(&ri.mac)
                .ok_or(AlienError::DevicesParseError)?
                .to_owned(),
        )?;

    for (frequency, devices_by_frequency) in frequencies {
        println!("\nfrequency: {:?}\n", frequency);

        let devices = devices_by_frequency
            .get("User network")
            .ok_or(AlienError::DevicesParseError)?;

        for (device_mac, device) in devices {
            println!("{} = {:?}\n", device_mac, device);
            DEVICE_HAPPINESS
                .with_label_values(&[device_mac, {
                    if !device.description.is_empty() {
                        &device.description
                    } else if !device.host_name.is_empty() {
                        &device.host_name
                    } else {
                        &device.address
                    }
                }])
                .set(device.happiness_score as f64)
        }
        println!("---");
    }
    Ok(())
}

fn get_client_with_old_cookie() -> Result<Client, AlienError> {
    let path = "cookie.txt";

    let input = File::open(path)?;
    let buffered = BufReader::new(input);

    let jar = Jar::default();

    for line in buffered.lines() {
        let url = format!("http://{BRIDGE_IP}", BRIDGE_IP = &BRIDGE_IP.as_str()).parse::<Url>()?;
        jar.add_cookie_str(&line?, &url);
    }

    let client = reqwest::Client::builder()
        .cookie_store(true)
        .cookie_provider(jar.into())
        .build()?;

    Ok(client)
}

fn get_client_with_no_cookie() -> Result<Client, AlienError> {
    // Enable the cookie_store for moving along the webui-session cookie
    Ok(reqwest::Client::builder().cookie_store(true).build()?)
}

async fn serve_req(_req: Request<Body>) -> Result<Response<Body>, AlienError> {
    let encoder = TextEncoder::new();

    HTTP_COUNTER.inc();
    let timer = HTTP_REQ_HISTOGRAM.with_label_values(&["all"]).start_timer();

    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer)?;
    HTTP_BODY_GAUGE.set(buffer.len() as f64);

    let response = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .body(Body::from(buffer))?;

    timer.observe_duration();

    Ok(response)
}

async fn main_loop() -> Result<(), AlienError> {
    let one_sec = tokio::time::Duration::from_secs(1);
    let thirty_secs = tokio::time::Duration::from_secs(30);

    // Default client
    let mut client = get_client_with_no_cookie()?;

    // Attempt to create a new client with a saved session cookie
    let cached_client_result = get_client_with_old_cookie();
    if cached_client_result.is_ok() {
        println!("DEBUG: Retrieved cached cookie");
        client = cached_client_result?;
    } else {
        println!("DEBUG: Unable to use cached cookie. Logging in again");
        login(&client).await?;
    }

    let mut metrics_token = {
        // It's possible the session cookie retrieved is expired
        // If this result is not ok, let the re-login in the loop occur
        let metrics_token_result = get_metrics_token(&client).await;
        if metrics_token_result.is_ok() {
            metrics_token_result?
        } else {
            String::from("")
        }
    };

    loop {
        let metrics = get_metrics(&client, metrics_token.as_str()).await;

        if metrics.is_ok() {
            print_metrics(metrics?)?;
            tokio::time::sleep(thirty_secs).await
        } else {
            println!("DEBUG: Session expired. Logging in again");
            login(&client).await?;
            metrics_token = get_metrics_token(&client).await?;
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
        _ = serve_future => {},
        _ = main_loop() => {},
    }

    Ok(())
}
