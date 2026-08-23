use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

pub const VERSION: &str = "2.0";

pub mod method {
    pub const PING: &str = "ping";
    pub const STATUS: &str = "status";
    pub const SURVEY_RUN: &str = "survey.run";
    pub const SCAN_START: &str = "scan.start";
    pub const QUARANTINE_LIST: &str = "quarantine.list";
    pub const QUARANTINE_RESTORE: &str = "quarantine.restore";
    pub const QUARANTINE_DELETE: &str = "quarantine.delete";

    pub const SCAN_PROGRESS: &str = "scan.progress";
    pub const SCAN_DETECTION: &str = "scan.detection";
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
    #[serde(default)]
    pub quarantine: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: u64,
    pub files_scanned: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: u64,
    pub original_path: String,
    pub engine: String,
    pub signature: String,
    pub size: u64,
    pub quarantined_at: u64,
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
            quarantine: true,
        };
        let value = serde_json::to_value(&params).unwrap();
        let back: ScanParams = serde_json::from_value(value).unwrap();
        assert!(back.quarantine);
        assert_eq!(back.paths.len(), 1);
    }
}
