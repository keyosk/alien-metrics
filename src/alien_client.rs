use crate::errors::AlienError;
use crate::metrics::Metrics;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, env, fs::File, io::Write, sync::Arc};

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

#[derive(Debug, Clone)]
pub struct AlienClient {
    pub client: Client,
    pub session_cookie: String,
    pub metrics_token: String,
    pub bridge_ip: String,
}

impl AlienClient {
    pub async fn new() -> Result<Self, AlienError> {
        let mut client = Self {
            client: Client::default(),
            session_cookie: get_cached_cookie(),
            metrics_token: String::default(),
            bridge_ip: env::var("BRIDGE_IP").expect("env BRIDGE_IP"),
        };

        if client.session_cookie.is_empty() {
            println!("Empty session token.... logging in...");
            client.login().await?;
        }

        if client.capture_metrics_token().await.is_err() {
            // It's possible the cached session cookie is no longer valid
            // If the next login and capture fails, bail out with error
            client.re_login().await?;
        }

        Ok(client)
    }

    async fn get_login_token(&self) -> Result<String, AlienError> {
        // Step 1: Get login token

        let login_url = format!("http://{}/login.php", self.bridge_ip);
        let login_token_response = self.client.get(login_url).send().await?.text().await?;

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

        let router_password = env::var("ROUTER_PASSWORD").expect("env ROUTER_PASSWORD");
        let login_params = [
            ("token", &self.get_login_token().await?),
            ("password", &router_password),
        ];

        let login_url = format!("http://{}/login.php", self.bridge_ip);
        let res = self
            .client
            .post(login_url)
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

        let info_url = format!("http://{}/info.php", self.bridge_ip);
        let metrics_token_response = self
            .client
            .get(info_url)
            .header("cookie", &self.session_cookie)
            .send()
            .await?
            .text()
            .await?;

        self.metrics_token = find_pattern(&metrics_token_response, r#"var token='"#, r#"'"#)
            .ok_or(AlienError::MetricsTokenMissingError)?
            .to_string();
        Ok(())
    }

    pub async fn re_login(&mut self) -> Result<(), AlienError> {
        self.login().await?;
        self.capture_metrics_token().await?;
        Ok(())
    }

    pub async fn get_metrics(&self) -> Result<AlienMetricsRoot, AlienError> {
        // Step 4: pull metrics json

        let metrics_params = [("do", "full"), ("token", &self.metrics_token)];

        let info_url = format!("http://{}/info-async.php", self.bridge_ip);
        let res = &self
            .client
            .post(info_url)
            .form(&metrics_params)
            .header("cookie", &self.session_cookie)
            .send()
            .await?
            .json::<AlienMetricsRoot>()
            .await?;

        Ok(res.to_vec())
    }

    pub fn record_metrics(
        &self,
        metrics: &Arc<Metrics>,
        res: AlienMetricsRoot,
    ) -> Result<(), AlienError> {
        for frequencies in res.get(1).ok_or(AlienError::DevicesParseError)?.values() {
            for networks in serde_json::from_value::<AlienMetrics>(frequencies.to_owned())?.values()
            {
                for devices in networks.values() {
                    for (device_mac, device) in devices {
                        metrics
                            .device_happiness_guage
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.happiness_score);
                        metrics
                            .device_signal_guage
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.signal_quality);
                        metrics
                            .device_rx_bitrate_guage
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.rx_bitrate);
                        metrics
                            .device_tx_bitrate_guage
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.tx_bitrate);
                        metrics
                            .device_rx_bytes_guage
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.rx_bytes);
                        metrics
                            .device_tx_bytes_guage
                            .with_label_values(&[device_mac, device.get_name()])
                            .set(device.tx_bytes);
                    }
                }
            }
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

fn get_cached_cookie() -> String {
    if let Ok(session_cookie) = std::fs::read_to_string("cookie.txt") {
        session_cookie
    } else {
        String::new()
    }
}
