use thiserror::Error;

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
    MetricsTokenMissingError(String),
    #[error("invalid password error")]
    InvalidPasswordError(String),
    #[error("login token missing error")]
    LoginTokenMissingError(String),
    #[error("devices list parse error")]
    DevicesParseError,
    #[error("metrics parse error")]
    MetricsParseError(#[from] serde_json::Error),
    #[error("axum error")]
    AxumError(#[from] axum::Error),
    #[error("axum http error")]
    AxumHTTPError(#[from] axum::http::Error),
    #[error("prometheus error")]
    PrometheusError(#[from] prometheus::Error),
}
