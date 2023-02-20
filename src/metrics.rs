use crate::errors::AlienError;
use prometheus::{labels, opts, register_counter, register_gauge_vec, Counter, GaugeVec};

pub struct Metrics {
    pub http_counter: Counter,
    pub scrape_counter: Counter,
    pub scrape_error_counter: Counter,
    pub device_happiness_gauge: GaugeVec,
    pub device_signal_gauge: GaugeVec,
    pub device_rx_bitrate_gauge: GaugeVec,
    pub device_tx_bitrate_gauge: GaugeVec,
    pub device_rx_bytes_gauge: GaugeVec,
    pub device_rx_bytes64_gauge: GaugeVec,
    pub device_tx_bytes_gauge: GaugeVec,
    pub device_tx_bytes64_gauge: GaugeVec,
}

impl Metrics {
    pub fn new() -> Result<Self, AlienError> {
        Ok(Self {
            http_counter: register_counter!(opts!(
                "http_requests_total",
                "Number of HTTP requests made.",
                labels! {"handler" => "all",}
            ))?,
            scrape_counter: register_counter!(opts!(
                "scrape_requests_total",
                "Number of times scraped alien metrics endpoint.",
            ))?,
            scrape_error_counter: register_counter!(opts!(
                "scrape_requests_error_total",
                "Number of times scraped alien metrics endpoint and failed.",
            ))?,
            device_happiness_gauge: register_gauge_vec!(
                "device_happiness",
                "The Happiness score of each device.",
                &["mac", "name"]
            )?,
            device_signal_gauge: register_gauge_vec!(
                "device_signal",
                "The Signal score of each device.",
                &["mac", "name"]
            )?,
            device_rx_bitrate_gauge: register_gauge_vec!(
                "device_rx_bitrate",
                "The rx bitrate of each device.",
                &["mac", "name"]
            )?,
            device_tx_bitrate_gauge: register_gauge_vec!(
                "device_tx_bitrate",
                "The tx bitrate of each device.",
                &["mac", "name"]
            )?,
            device_rx_bytes_gauge: register_gauge_vec!(
                "device_rx_bytes",
                "The rx bytes of each device.",
                &["mac", "name"]
            )?,
            device_rx_bytes64_gauge: register_gauge_vec!(
                "device_rx_bytes64",
                "The rx bytes 64 of each device.",
                &["mac", "name"]
            )?,
            device_tx_bytes_gauge: register_gauge_vec!(
                "device_tx_bytes",
                "The tx bytes of each device.",
                &["mac", "name"]
            )?,
            device_tx_bytes64_gauge: register_gauge_vec!(
                "device_tx_bytes64",
                "The tx bytes 64 of each device.",
                &["mac", "name"]
            )?,
        })
    }
}
