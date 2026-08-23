use kariba_core::clamav;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Clean,
    Infected { signature: String },
    Error { message: String },
}

pub struct ClamdClient {
    reader: BufReader<UnixStream>,
    stream: UnixStream,
}

impl ClamdClient {
    pub fn connect() -> io::Result<Self> {
        let mut last_error = None;
        for candidate in clamav::socket_candidates() {
            match UnixStream::connect(&candidate) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
                    let reader = BufReader::new(stream.try_clone()?);
                    return Ok(Self { reader, stream });
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no clamd socket candidates")
        }))
    }

    pub fn scan_path(&mut self, path: &Path) -> io::Result<ScanOutcome> {
        let command = format!("SCAN {}\n", path.display());
        self.stream.write_all(command.as_bytes())?;
        self.stream.flush()?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        Ok(parse_scan_response(&line))
    }
}

pub fn parse_scan_response(line: &str) -> ScanOutcome {
    let line = line.trim();
    let Some((_, verdict)) = line.rsplit_once(": ") else {
        return ScanOutcome::Error {
            message: line.to_string(),
        };
    };
    let verdict = verdict.trim();

    if verdict == "OK" {
        return ScanOutcome::Clean;
    }
    if let Some(signature) = verdict.strip_suffix(" FOUND") {
        return ScanOutcome::Infected {
            signature: signature.trim().to_string(),
        };
    }
    if let Some(message) = verdict.strip_prefix("ERROR") {
        return ScanOutcome::Error {
            message: message.trim().trim_start_matches(':').trim().to_string(),
        };
    }
    ScanOutcome::Error {
        message: verdict.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean() {
        assert_eq!(parse_scan_response("/tmp/file: OK\n"), ScanOutcome::Clean);
    }

    #[test]
    fn parses_infected() {
        assert_eq!(
            parse_scan_response("/tmp/eicar.com: Eicar-Signature FOUND\n"),
            ScanOutcome::Infected {
                signature: "Eicar-Signature".into()
            }
        );
    }

    #[test]
    fn parses_error() {
        assert_eq!(
            parse_scan_response("/tmp/locked: ERROR: Can't open file\n"),
            ScanOutcome::Error {
                message: "Can't open file".into()
            }
        );
    }

    #[test]
    fn parses_path_with_colon() {
        assert_eq!(
            parse_scan_response("/tmp/weird: name: OK\n"),
            ScanOutcome::Clean
        );
    }

    #[test]
    fn parses_unexpected() {
        assert!(matches!(
            parse_scan_response("garbage"),
            ScanOutcome::Error { .. }
        ));
    }
}
