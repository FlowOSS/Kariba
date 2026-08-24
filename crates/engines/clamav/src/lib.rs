use kariba_core::clamav;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

const KEEPALIVE_AFTER: Duration = Duration::from_secs(3);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const INSTREAM_CHUNK: usize = 64 * 1024;
// clamd's default StreamMaxLength; larger files fall back to a path-based
// SCAN where clamd opens the file itself.
const STREAM_MAX: u64 = 25 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanOutcome {
    Clean,
    Infected { signature: String },
    Error { message: String },
}

pub struct ClamdClient {
    reader: BufReader<UnixStream>,
    stream: UnixStream,
    last_command: Instant,
    read_timeout: Duration,
}

impl ClamdClient {
    pub fn connect() -> io::Result<Self> {
        Self::connect_with_read_timeout(READ_TIMEOUT)
    }

    /// Real-time verdicts need a short, bounded read timeout so a slow engine
    /// can never hold a permission event's syscall hostage.
    pub fn connect_with_read_timeout(read_timeout: Duration) -> io::Result<Self> {
        let mut last_error = None;
        for candidate in clamav::socket_candidates() {
            match UnixStream::connect(&candidate) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(read_timeout))?;
                    let reader = BufReader::new(stream.try_clone()?);
                    return Ok(Self {
                        reader,
                        stream,
                        last_command: Instant::now(),
                        read_timeout,
                    });
                }
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no clamd socket candidates")
        }))
    }

    pub fn scan_path(&mut self, path: &Path) -> io::Result<ScanOutcome> {
        match self.scan_once(path) {
            Ok(outcome) => Ok(outcome),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::TimedOut
                ) =>
            {
                let timeout = self.read_timeout;
                *self = Self::connect_with_read_timeout(timeout)?;
                self.scan_once(path)
            }
            Err(e) => Err(e),
        }
    }

    /// Single scan attempt with no reconnect-retry: a timeout here means the
    /// verdict budget is spent, and the caller fails open instead of waiting
    /// for a retry.
    pub fn scan_path_once(&mut self, path: &Path) -> io::Result<ScanOutcome> {
        self.scan_once(path)
    }

    fn scan_once(&mut self, path: &Path) -> io::Result<ScanOutcome> {
        if self.last_command.elapsed() > KEEPALIVE_AFTER {
            self.keepalive()?;
        }
        // Stream the file contents to clamd (INSTREAM) instead of sending
        // the path: karibad runs as root and can open anything, while clamd
        // runs as the unprivileged `clamav` user, which cannot traverse
        // mode-700 home directories. Path-based SCAN is only used for files
        // beyond clamd's StreamMaxLength.
        let use_instream = fs::metadata(path)
            .map(|m| m.len() <= STREAM_MAX)
            .unwrap_or(true);
        let outcome = if use_instream {
            self.instream(path)
        } else {
            self.scan_command(path)
        };
        self.last_command = Instant::now();
        outcome
    }

    fn scan_command(&mut self, path: &Path) -> io::Result<ScanOutcome> {
        let command = format!("SCAN {}\n", path.display());
        self.stream.write_all(command.as_bytes())?;
        self.stream.flush()?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        Ok(parse_scan_response(&line))
    }

    fn instream(&mut self, path: &Path) -> io::Result<ScanOutcome> {
        let mut file = fs::File::open(path)?;
        self.stream.write_all(b"zINSTREAM\0")?;
        let mut buf = vec![0u8; INSTREAM_CHUNK];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            self.stream.write_all(&(n as u32).to_be_bytes())?;
            self.stream.write_all(&buf[..n])?;
        }
        self.stream.write_all(&0u32.to_be_bytes())?;
        self.stream.flush()?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        Ok(parse_scan_response(&line))
    }

    fn keepalive(&mut self) -> io::Result<()> {
        self.stream.write_all(b"VERSION\n")?;
        self.stream.flush()?;
        let mut line = String::new();
        self.reader.read_line(&mut line)?;
        self.last_command = Instant::now();
        Ok(())
    }
}

pub fn parse_scan_response(line: &str) -> ScanOutcome {
    // INSTREAM responses are NUL-terminated ("stream: OK\0"); SCAN responses
    // are newline-terminated. Strip both.
    let line = line.trim().trim_end_matches('\0');
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

    #[test]
    #[ignore = "requires a running clamd"]
    fn instream_detects_eicar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eicar.txt");
        std::fs::write(
            &path,
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        )
        .unwrap();
        let mut client = ClamdClient::connect().unwrap();
        let outcome = client.scan_path(&path).unwrap();
        assert!(
            matches!(outcome, ScanOutcome::Infected { .. }),
            "expected Infected, got {outcome:?}"
        );
    }

    #[test]
    #[ignore = "requires a running clamd"]
    fn concurrent_scans_do_not_serialize() {
        // While connection A scans a large file, a fresh connection B must
        // still get a fast verdict — otherwise exec verdicts starve behind
        // background scans.
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("big.bin");
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&big).unwrap();
            let chunk = vec![0xABu8; 1024 * 1024];
            for _ in 0..20 {
                f.write_all(&chunk).unwrap();
            }
        }
        let small = dir.path().join("small.txt");
        std::fs::write(&small, "hello world").unwrap();

        let big_path = big.clone();
        let big_thread = std::thread::spawn(move || {
            let mut a = ClamdClient::connect().unwrap();
            let t = std::time::Instant::now();
            let outcome = a.scan_path(&big_path).unwrap();
            (t.elapsed(), outcome)
        });
        std::thread::sleep(std::time::Duration::from_millis(300));
        let mut b = ClamdClient::connect().unwrap();
        let t = std::time::Instant::now();
        let small_outcome = b.scan_path(&small).unwrap();
        let small_elapsed = t.elapsed();
        let (big_elapsed, big_outcome) = big_thread.join().unwrap();
        println!(
            "big: {big_elapsed:?} ({big_outcome:?}) · small while big in flight: {small_elapsed:?} ({small_outcome:?})"
        );
        assert!(
            small_elapsed < std::time::Duration::from_secs(2),
            "small scan was blocked behind the big scan — clamd serializes"
        );
    }
}
