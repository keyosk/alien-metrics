use crate::errors::AlienError;
use crate::metrics::Metrics;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, env, fs::File, io::Write, sync::Arc};
use tokio::time::Duration;
use tracing::info;

type AlienInfoRoot = Vec<HashMap<String, Value>>;
type AlienInfo = HashMap<String, HashMap<String, HashMap<String, Device>>>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "PascalCase")]
struct Device {
    address: String,
    description: String,
    happiness_score: f64,
    host_name: String,
    inactive: f64,
    lease_validity: f64,
    mac: String,
    max_bandwidth: f64,
    max_spatial_streams: f64,
    mode: String,
    radio_mode: String,
    rx_bitrate: f64,
    rx_bytes: f64,
    rx_bytes64: f64,
    #[serde(rename = "RxBytes_5sec")]
    rx_bytes_5sec: f64,
    #[serde(rename = "RxBytes_15sec")]
    rx_bytes_15sec: f64,
    #[serde(rename = "RxBytes_30sec")]
    rx_bytes_30sec: f64,
    #[serde(rename = "RxBytes_60sec")]
    rx_bytes_60sec: f64,
    rx_mcs: f64,
    rx_mhz: f64,
    signal_quality: f64,
    tx_bitrate: f64,
    tx_bytes: f64,
    tx_bytes64: f64,
    #[serde(rename = "TxBytes_5sec")]
    tx_bytes_5sec: f64,
    #[serde(rename = "TxBytes_15sec")]
    tx_bytes_15sec: f64,
    #[serde(rename = "TxBytes_30sec")]
    tx_bytes_30sec: f64,
    #[serde(rename = "TxBytes_60sec")]
    tx_bytes_60sec: f64,
    tx_mcs: f64,
    tx_mhz: f64,
}

impl Device {
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

#[derive(Debug, Clone)]
pub struct AlienClient {
    client: Client,
    session_cookie: String,
    metrics_token: String,
    host: String,
    password: String,
}

impl AlienClient {
    pub async fn new() -> Result<Self, AlienError> {
        let mut client = Self {
            client: Client::default(),
            session_cookie: get_cached_cookie(),
            metrics_token: String::default(),
            host: env::var("ROUTER_HOST").unwrap_or(String::from("amplifi.lan")),
            password: env::var("ROUTER_PASSWORD").expect("env ROUTER_PASSWORD"),
        };

        if client.session_cookie.is_empty() {
            info!("Empty session token.... logging in...");
            client.login().await?;
        }

        if let Err(e) = client.capture_metrics_token().await {
            info!("Unable to capture initial metrics token: {:?}", e);
            client.re_login().await?;
        }

        Ok(client)
    }

    async fn get_login_token(&self) -> Result<String, AlienError> {
        // Step 1: Get login token

        let login_url = format!("http://{}/login.php", self.host);
        let login_token_response = self
            .client
            .get(login_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .text()
            .await?;

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

        let login_params = [
            ("token", &self.get_login_token().await?),
            ("password", &self.password),
        ];

        let login_url = format!("http://{}/login.php", self.host);
        let res = self
            .client
            .post(login_url)
            .form(&login_params)
            .timeout(Duration::from_secs(5))
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

        set_cached_cookie(&self.session_cookie)?;

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

        let info_url = format!("http://{}/info.php", self.host);
        let metrics_token_response = self
            .client
            .get(info_url)
            .header("cookie", &self.session_cookie)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| {
                AlienError::MetricsTokenMissingError(String::from("unable to send request"))
            })?
            .text()
            .await
            .map_err(|_| {
                AlienError::MetricsTokenMissingError(String::from(
                    "unable to retrieve response body",
                ))
            })?;

        self.metrics_token = find_pattern(&metrics_token_response, r#"var token='"#, r#"'"#)
            .ok_or(AlienError::MetricsTokenMissingError(String::from(
                "unable to find token in response",
            )))?
            .to_string();
        Ok(())
    }

    pub async fn re_login(&mut self) -> Result<(), AlienError> {
        info!("Logging in again...");
        self.login().await?;
        self.capture_metrics_token().await?;
        Ok(())
    }

    pub async fn get_info(&self) -> Result<AlienInfoRoot, AlienError> {
        // Step 4: pull info json

        let metrics_params = [("do", "full"), ("token", &self.metrics_token)];

        let info_url = format!("http://{}/info-async.php", self.host);
        let res = &self
            .client
            .post(info_url)
            .form(&metrics_params)
            .header("cookie", &self.session_cookie)
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .json::<AlienInfoRoot>()
            .await?;

        Ok(res.to_vec())
    }

    pub fn record_metrics(
        &self,
        metrics: &Arc<Metrics>,
        res: AlienInfoRoot,
    ) -> Result<(), AlienError> {
        for device in get_devices(res)? {
            metrics
                .device_happiness_gauge
                .with_label_values(&[device.mac.as_str(), device.get_name()])
                .set(device.happiness_score);
            metrics
                .device_signal_gauge
                .with_label_values(&[device.mac.as_str(), device.get_name()])
                .set(device.signal_quality);
            metrics
                .device_rx_bitrate_gauge
                .with_label_values(&[device.mac.as_str(), device.get_name()])
                .set(device.rx_bitrate);
            metrics
                .device_tx_bitrate_gauge
                .with_label_values(&[device.mac.as_str(), device.get_name()])
                .set(device.tx_bitrate);
            metrics
                .device_rx_bytes_gauge
                .with_label_values(&[device.mac.as_str(), device.get_name()])
                .set(device.rx_bytes);
            metrics
                .device_tx_bytes_gauge
                .with_label_values(&[device.mac.as_str(), device.get_name()])
                .set(device.tx_bytes);
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

fn set_cached_cookie(session_cookie: &str) -> Result<(), std::io::Error> {
    write!(File::create("cookie.txt")?, "{}", session_cookie)
}

fn get_devices(res: AlienInfoRoot) -> Result<Vec<Device>, AlienError> {
    let mut devices_vec: Vec<Device> = vec![];
    for frequencies in res.get(1).ok_or(AlienError::DevicesParseError)?.values() {
        for (network_type, networks) in
            serde_json::from_value::<AlienInfo>(frequencies.to_owned())?.iter_mut()
        {
            if network_type != "Internal network" {
                for devices in networks.values_mut() {
                    for (device_mac, device) in devices {
                        device.mac = device_mac.to_string();
                        devices_vec.push(device.to_owned());
                    }
                }
            }
        }
    }
    Ok(devices_vec)
}

#[cfg(test)]
mod tests {

    use super::{get_devices, AlienClient, AlienError, AlienInfoRoot, Client};
    use mockito::Server;
    use once_cell::sync::Lazy;

    static MOCK_DATA: Lazy<String> =
        Lazy::new(|| std::fs::read_to_string("mocks/single_router.json").unwrap());

    static MOCK_DATA_MULTI_ROUTER: Lazy<String> =
        Lazy::new(|| std::fs::read_to_string("mocks/multi_router.json").unwrap());

    #[tokio::test]
    async fn test_get_info() {
        let mut server = Server::new_async().await;

        let client = AlienClient {
            client: Client::default(),
            session_cookie: String::default(),
            metrics_token: String::default(),
            host: server.host_with_port(),
            password: String::default(),
        };

        let get_info_mock = server
            .mock("POST", "/info-async.php")
            .with_body(MOCK_DATA.to_string())
            .create_async()
            .await;

        let info: Result<AlienInfoRoot, AlienError> = client.get_info().await;

        // Ensure mock was called
        get_info_mock.assert_async().await;

        // Ensure info was parsed into the expected
        assert!(info.is_ok(), "failed to parse info");
    }

    #[tokio::test]
    async fn test_get_devices() {
        let mut server = Server::new_async().await;

        let client = AlienClient {
            client: Client::default(),
            session_cookie: String::default(),
            metrics_token: String::default(),
            host: server.host_with_port(),
            password: String::default(),
        };

        let get_info_mock = server
            .mock("POST", "/info-async.php")
            .with_body(MOCK_DATA.to_string())
            .create_async()
            .await;

        let info: Result<AlienInfoRoot, AlienError> = client.get_info().await;

        // Ensure mock was called
        get_info_mock.assert_async().await;

        // Ensure info was parsed into the expected
        assert!(info.is_ok(), "failed to parse info");

        let devices = get_devices(info.unwrap()).unwrap();

        assert_eq!(devices.len(), 4, "failed to find 4 devices");

        let expected_macs = [
            String::from("0F:4C:53:B9:5C:BF"),
            String::from("0A:C6:8A:ED:D0:E9"),
            String::from("BF:2D:B9:49:5E:01"),
            String::from("00:2C:72:AA:29:4D"),
        ];

        for device in devices {
            assert!(
                expected_macs.contains(&device.mac),
                "expected mac addresses not found"
            );
        }
    }
    #[tokio::test]
    async fn test_get_info_multi_router() {
        let mut server = Server::new_async().await;

        let client = AlienClient {
            client: Client::default(),
            session_cookie: String::default(),
            metrics_token: String::default(),
            host: server.host_with_port(),
            password: String::default(),
        };

        let get_info_mock = server
            .mock("POST", "/info-async.php")
            .with_body(MOCK_DATA_MULTI_ROUTER.to_string())
            .create_async()
            .await;

        let info: Result<AlienInfoRoot, AlienError> = client.get_info().await;

        // Ensure mock was called
        get_info_mock.assert_async().await;

        // Ensure info was parsed into the expected
        assert!(info.is_ok(), "failed to parse info");
    }

    #[tokio::test]
    async fn test_get_devices_multi_router() {
        let mut server = Server::new_async().await;

        let client = AlienClient {
            client: Client::default(),
            session_cookie: String::default(),
            metrics_token: String::default(),
            host: server.host_with_port(),
            password: String::default(),
        };

        let get_info_mock = server
            .mock("POST", "/info-async.php")
            .with_body(MOCK_DATA_MULTI_ROUTER.to_string())
            .create_async()
            .await;

        let info: Result<AlienInfoRoot, AlienError> = client.get_info().await;

        // Ensure mock was called
        get_info_mock.assert_async().await;

        // Ensure info was parsed into the expected
        assert!(info.is_ok(), "failed to parse info");

        let devices = get_devices(info.unwrap()).unwrap();

        assert_eq!(devices.len(), 4, "failed to find 4 devices");

        let expected_macs = [
            String::from("0F:4C:53:B9:5C:BF"),
            String::from("0A:C6:8A:ED:D0:E9"),
            String::from("BF:2D:B9:49:5E:01"),
            String::from("00:2C:72:AA:29:4D"),
        ];

        for device in devices {
            assert!(
                expected_macs.contains(&device.mac),
                "expected mac addresses not found"
            );
        }
    }
}
