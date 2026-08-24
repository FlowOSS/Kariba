use kariba_ipc::Notification;
use kariba_ipc::client::send;
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// Registry of live client connections for daemon-originated notifications
// (real-time detections). Each connection registers a cloned writer on
// connect and unregisters by id on disconnect; broadcasts additionally
// prune writers that fail to send. Messages are short single-write lines,
// so a broadcast cannot interleave with a connection's own responses.
pub struct Broadcaster {
    writers: Mutex<HashMap<u64, UnixStream>>,
    next_id: AtomicU64,
}

impl Broadcaster {
    pub fn new() -> Self {
        Self {
            writers: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn register(&self, stream: &UnixStream) -> Option<u64> {
        let writer = stream.try_clone().ok()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.writers.lock().ok()?.insert(id, writer);
        Some(id)
    }

    pub fn unregister(&self, id: u64) {
        if let Ok(mut writers) = self.writers.lock() {
            writers.remove(&id);
        }
    }

    pub fn broadcast(&self, notification: &Notification) {
        let Ok(mut writers) = self.writers.lock() else {
            return;
        };
        writers.retain(|_, stream| send(stream, notification).is_ok());
    }
}
