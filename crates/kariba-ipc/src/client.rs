use crate::protocol::{
    Notification, Request, Response, RpcError, WireMessage, error_code, parse_line,
};
use serde::Serialize;
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub struct Client {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    next_id: u64,
}

impl Client {
    pub fn connect(path: &Path) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        let reader = BufReader::new(stream.try_clone()?);
        Ok(Self {
            stream,
            reader,
            next_id: 1,
        })
    }
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        let mut ignore = |_: &Notification| {};
        self.call_with_notifications(method, params, &mut ignore)
    }

    pub fn call_with_notifications<F>(
        &mut self,
        method: &str,
        params: Value,
        mut on_notify: F,
    ) -> Result<Value, RpcError>
    where
        F: FnMut(&Notification),
    {
        let id = self.next_id;
        self.next_id += 1;

        send(&mut self.stream, &Request::new(id, method, params))?;

        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))?;
            if n == 0 {
                return Err(RpcError::new(
                    error_code::SERVER_ERROR,
                    "connection closed by daemon",
                ));
            }

            match parse_line(line.trim_end())? {
                WireMessage::Notification(notification) => on_notify(&notification),
                WireMessage::Response(response) if response.id == id => {
                    if let Some(error) = response.error {
                        return Err(error);
                    }
                    return Ok(response.result.unwrap_or(Value::Null));
                }
                _ => {}
            }
        }
    }
    /// Read notifications until the connection closes. Used by subscribers
    /// that hold a connection open purely to receive daemon broadcasts.
    pub fn subscribe<F>(&mut self, mut on_notify: F) -> Result<(), RpcError>
    where
        F: FnMut(&Notification),
    {
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))?;
            if n == 0 {
                return Err(RpcError::new(
                    error_code::SERVER_ERROR,
                    "connection closed by daemon",
                ));
            }
            if let WireMessage::Notification(notification) = parse_line(line.trim_end())? {
                on_notify(&notification);
            }
        }
    }
}

/// Connect to the daemon, trying the socket candidates in order
/// (same-user daemon first, then the root daemon's well-known socket).
pub fn connect_daemon() -> std::io::Result<Client> {
    let mut last = None;
    for path in kariba_core::paths::socket_candidates() {
        match Client::connect(&path) {
            Ok(client) => return Ok(client),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "no socket candidates")
    }))
}

pub fn send<W: Write, T: Serialize>(writer: &mut W, message: &T) -> Result<(), RpcError> {
    let mut line = serde_json::to_string(message)
        .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))?;
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))?;
    writer
        .flush()
        .map_err(|e| RpcError::new(error_code::SERVER_ERROR, e.to_string()))
}

pub type Incoming = std::io::Lines<BufReader<UnixStream>>;

pub fn reader(stream: &UnixStream) -> std::io::Result<BufReader<UnixStream>> {
    Ok(BufReader::new(stream.try_clone()?))
}

pub fn respond(writer: &mut UnixStream, id: u64, result: Result<Value, RpcError>) {
    let response = match result {
        Ok(value) => Response::ok(id, value),
        Err(error) => Response::err(id, error),
    };
    let _ = send(writer, &response);
}
