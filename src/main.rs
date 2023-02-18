use once_cell::sync::Lazy;
use reqwest::{cookie::Jar, Client, Url};
use serde_json::Value;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader, Write},
    thread, time,
};
use thiserror::Error;

static LOGIN_PASSWORD: Lazy<String> =
    Lazy::new(|| env::var("ROUTER_PASSWORD").expect("env ROUTER_PASSWORD"));
static BRIDGE_IP: Lazy<String> =
    Lazy::new(|| env::var("BRIDGE_IP").unwrap_or(String::from("192.168.188.1")));

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

#[derive(Error, Debug)]
pub enum AlienError {
    #[error("reqwest error")]
    ReqwestSad(#[from] reqwest::Error),
    #[error("token cache r/w error")]
    FileSad(#[from] std::io::Error),
    #[error("bad BRIDGE_IP config")]
    BridgeIPSad(#[from] url::ParseError),
    #[error("cookie probs")]
    CookieSad(#[from] reqwest::header::ToStrError),
    #[error("Could not parse metrics token")]
    MetricsTokenMissing,
    #[error("Invalid Password")]
    BadPassword(String),
    #[error("Could not parse login token")]
    LoginTokenMissing(String),
    #[error("unable to parse Alien devices response")]
    DevicesParseError,
    #[error("unknown alien error")]
    Unknown,
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
        .ok_or(AlienError::LoginTokenMissing(login_token_response.clone()))?;

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
        .ok_or(AlienError::BadPassword(String::from("No cookie returned")))?;

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
        Err(AlienError::BadPassword(String::from("Invalid password")))
    } else {
        Err(AlienError::BadPassword(String::from("Unexpected response")))
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
        .ok_or(AlienError::MetricsTokenMissing)?;

    Ok(String::from(metrics_token))
}

async fn get_metrics(client: &Client, metrics_token: &str) -> Result<Value, AlienError> {
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
        .json::<serde_json::Value>()
        .await?;

    Ok(res)
}

fn print_metrics(res: Value) -> Result<(), AlienError> {
    let mut res_array = res.as_array().ok_or(AlienError::DevicesParseError)?.iter();

    // remove first item from res_array, it's the router info
    let router_info = res_array
        .next()
        .ok_or(AlienError::DevicesParseError)?
        .as_object()
        .ok_or(AlienError::DevicesParseError)?;

    let router_mac = router_info
        .keys()
        .next()
        .ok_or(AlienError::DevicesParseError)?;

    println!("router_mac: {:?}", router_mac);

    // remove second item from res_array, it's the devices list
    let frequencies = res_array
        .next()
        .ok_or(AlienError::DevicesParseError)?
        .as_object()
        .ok_or(AlienError::DevicesParseError)?
        .get(router_mac)
        .ok_or(AlienError::DevicesParseError)?
        .as_object()
        .ok_or(AlienError::DevicesParseError)?;

    for (frequency, devices_by_frequency) in frequencies {
        println!("\nfrequency: {:?}\n", frequency);

        let devices = devices_by_frequency
            .get("User network")
            .ok_or(AlienError::DevicesParseError)?
            .as_object()
            .ok_or(AlienError::DevicesParseError)?;

        for (device_mac, device) in devices {
            println!("device_mac: {:?}", device_mac);
            println!("device: {:?}\n", device);
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

#[tokio::main]
async fn main() -> Result<(), AlienError> {
    let one_sec = time::Duration::from_secs(1);
    let thirty_secs = time::Duration::from_secs(30);

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
            thread::sleep(thirty_secs);
        } else {
            println!("DEBUG: Session expired. Logging in again");
            login(&client).await?;
            metrics_token = get_metrics_token(&client).await?;
            thread::sleep(one_sec);
        }
    }
}
