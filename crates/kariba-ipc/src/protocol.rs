use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub use kariba_core::config::Settings;

pub const VERSION: &str = "2.0";

pub mod method {
    pub const PING: &str = "ping";
    pub const STATUS: &str = "status";
    pub const SURVEY_RUN: &str = "survey.run";
    pub const SCAN_START: &str = "scan.start";
    pub const SCAN_CANCEL: &str = "scan.cancel";
    pub const SCAN_HISTORY: &str = "scan.history";
    pub const THREATS_LIST: &str = "threats.list";
    pub const QUARANTINE_LIST: &str = "quarantine.list";
    pub const QUARANTINE_RESTORE: &str = "quarantine.restore";
    pub const QUARANTINE_DELETE: &str = "quarantine.delete";
    pub const SETTINGS_GET: &str = "settings.get";
    pub const SETTINGS_SET: &str = "settings.set";

    pub const SCAN_PROGRESS: &str = "scan.progress";
    pub const SCAN_DETECTION: &str = "scan.detection";
    pub const REALTIME_DETECTION: &str = "realtime.detection";
}

pub mod error_code {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    pub const SERVER_ERROR: i64 = -32000;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl Request {
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: VERSION.into(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
}

impl Notification {
    pub fn new(method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: VERSION.into(),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rpc error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for RpcError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: VERSION.into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, error: RpcError) -> Self {
        Self {
            jsonrpc: VERSION.into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone)]
pub enum WireMessage {
    Request(Request),
    Notification(Notification),
    Response(Response),
}

pub fn parse_line(line: &str) -> Result<WireMessage, RpcError> {
    let value: Value = serde_json::from_str(line)
        .map_err(|e| RpcError::new(error_code::PARSE_ERROR, e.to_string()))?;

    if let Some(method) = value.get("method").and_then(Value::as_str) {
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        return match value.get("id").and_then(Value::as_u64) {
            Some(id) => Ok(WireMessage::Request(Request {
                jsonrpc: VERSION.into(),
                id,
                method: method.into(),
                params,
            })),
            None => Ok(WireMessage::Notification(Notification {
                jsonrpc: VERSION.into(),
                method: method.into(),
                params,
            })),
        };
    }

    if let Some(id) = value.get("id").and_then(Value::as_u64) {
        let result = value.get("result").cloned();
        let error = value
            .get("error")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| RpcError::new(error_code::PARSE_ERROR, e.to_string()))?;
        return Ok(WireMessage::Response(Response {
            jsonrpc: VERSION.into(),
            id,
            result,
            error,
        }));
    }

    Err(RpcError::new(
        error_code::INVALID_REQUEST,
        "message has neither method nor id",
    ))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanParams {
    pub paths: Vec<PathBuf>,
    // None means "use the daemon's scan.default_quarantine setting".
    #[serde(default)]
    pub quarantine: Option<bool>,
    // "quick" | "full" | "custom" — recorded in scan history.
    #[serde(default = "default_scan_kind")]
    pub kind: String,
}

fn default_scan_kind() -> String {
    "custom".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryItem {
    pub id: u64,
    pub kind: String,
    pub paths: Vec<String>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatStatusFilter {
    #[serde(default)]
    pub status: Option<String>,
}

// One row per detection event; identical files detected repeatedly are
// separate rows. status: detected | quarantined | restored | deleted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatHistoryItem {
    pub id: u64,
    pub path: String,
    pub sha256: String,
    pub engine: String,
    pub signature: String,
    pub detected_at: u64,
    pub status: String,
    // "scan" | "realtime"
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: u64,
    pub files_scanned: u64,
    pub files_total: u64,
    pub threats_found: u32,
    pub current: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub path: String,
    pub engine: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: u64,
    pub files_scanned: u64,
    pub threats_found: u32,
    pub quarantined: u32,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResult {
    pub daemon_version: String,
    pub uptime_secs: u64,
    pub scans_total: u64,
    pub threats_total: u64,
    pub quarantined_items: u64,
    pub protection_enabled: bool,
    pub realtime_active: bool,
    pub realtime_detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeDetection {
    pub path: String,
    pub engine: String,
    pub signature: String,
    // "detected" | "quarantined" | "denied" | "denied+quarantined"
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsSetParams {
    pub settings: Settings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: u64,
    pub original_path: String,
    pub engine: String,
    pub signature: String,
    pub size: u64,
    pub quarantined_at: u64,
    // "scan" | "realtime"; default keeps older daemons decodable
    #[serde(default)]
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdParams {
    pub id: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request() {
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"ping","params":null}"#;
        let WireMessage::Request(req) = parse_line(line).unwrap() else {
            panic!("expected request")
        };
        assert_eq!(req.id, 7);
        assert_eq!(req.method, "ping");
    }

    #[test]
    fn parses_notification_without_id() {
        let line = r#"{"jsonrpc":"2.0","method":"scan.progress","params":{"files_scanned":1}}"#;
        let WireMessage::Notification(n) = parse_line(line).unwrap() else {
            panic!("expected notification")
        };
        assert_eq!(n.method, "scan.progress");
    }

    #[test]
    fn parses_response_with_result() {
        let line = r#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#;
        let WireMessage::Response(r) = parse_line(line).unwrap() else {
            panic!("expected response")
        };
        assert_eq!(r.id, 3);
        assert!(r.error.is_none());
    }

    #[test]
    fn parses_response_with_error() {
        let line = r#"{"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"not found"}}"#;
        let WireMessage::Response(r) = parse_line(line).unwrap() else {
            panic!("expected response")
        };
        assert_eq!(r.error.unwrap().code, -32601);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_line("not json").is_err());
        assert!(parse_line(r#"{"jsonrpc":"2.0"}"#).is_err());
    }

    #[test]
    fn roundtrip_scan_params() {
        let params = ScanParams {
            paths: vec![PathBuf::from("/tmp")],
            quarantine: Some(true),
            kind: "quick".into(),
        };
        let value = serde_json::to_value(&params).unwrap();
        let back: ScanParams = serde_json::from_value(value).unwrap();
        assert_eq!(back.quarantine, Some(true));
        assert_eq!(back.paths.len(), 1);
        assert_eq!(back.kind, "quick");
    }

    #[test]
    fn scan_params_kind_defaults_to_custom() {
        let value = serde_json::json!({ "paths": ["/tmp"], "quarantine": false });
        let params: ScanParams = serde_json::from_value(value).unwrap();
        assert_eq!(params.kind, "custom");
        assert_eq!(params.quarantine, Some(false));
    }

    #[test]
    fn scan_params_quarantine_defaults_to_none() {
        let value = serde_json::json!({ "paths": ["/tmp"] });
        let params: ScanParams = serde_json::from_value(value).unwrap();
        assert_eq!(params.quarantine, None);
    }

    #[test]
    fn roundtrip_settings_set_params() {
        let mut settings = Settings::default();
        settings.realtime.enabled = false;
        let params = SettingsSetParams {
            settings: settings.clone(),
        };
        let value = serde_json::to_value(&params).unwrap();
        let back: SettingsSetParams = serde_json::from_value(value).unwrap();
        assert_eq!(back.settings, settings);
    }
}
