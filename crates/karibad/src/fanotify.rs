//! Thin safe wrapper over the fanotify(7) syscall ABI.
//!
//! Uses the classic fd-based event format (no FAN_REPORT_FID): every event
//! carries an open fd to the affected file, which the daemon must close
//! after handling. Permission events (`FAN_OPEN_EXEC_PERM`) hold the
//! calling process's syscall until a `fanotify_response` is written.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// fanotify_init flags
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_CLASS_CONTENT: libc::c_uint = 0x0000_0004;
// Deliberately NOT using FAN_UNLIMITED_QUEUE: an unlimited kernel queue
// plus any reader stall pins one fd + inode per pending event system-wide
// (that froze a machine on 2026-08-24). The bounded queue overflows with a
// FAN_Q_OVERFLOW event instead — detectable, recoverable loss.
const FAN_UNLIMITED_MARKS: libc::c_uint = 0x0000_0020;

// fanotify_mark flags
const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MARK_MOUNT: libc::c_uint = 0x0000_0010;

// Event mask bits
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

// Verdicts
const FAN_ALLOW: u32 = 1;
const FAN_DENY: u32 = 2;

const FANOTIFY_METADATA_VERSION: u8 = 3;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct EventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct Response {
    fd: i32,
    response: u32,
}

#[derive(Debug)]
pub struct Event {
    pub mask: u64,
    pub fd: RawFd,
    // Reserved for process-based exclusions (a planned settings field).
    #[allow(dead_code)]
    pub pid: i32,
}

/// fanotify group in CONTENT class (required for permission events) with
/// unlimited marks but a BOUNDED event queue — overflow is reported via
/// FAN_Q_OVERFLOW rather than pinning unbounded kernel resources.
pub fn init() -> io::Result<RawFd> {
    let flags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_UNLIMITED_MARKS;
    let event_flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as libc::c_uint;
    let fd = unsafe { libc::fanotify_init(flags, event_flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn mark_mount(fan_fd: RawFd, mount_point: &Path, mask: u64) -> io::Result<()> {
    mark(fan_fd, FAN_MARK_ADD, mount_point, mask)
}

fn mark(fan_fd: RawFd, action: libc::c_uint, mount_point: &Path, mask: u64) -> io::Result<()> {
    let c_path = CString::new(mount_point.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let ret = unsafe {
        libc::fanotify_mark(
            fan_fd,
            action | FAN_MARK_MOUNT,
            mask,
            libc::AT_FDCWD,
            c_path.as_ptr(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Blocks until at least one event is available, then returns all events in
/// the read buffer. Event fds are owned by the caller and must be closed.
pub fn read_events(fan_fd: RawFd, buf: &mut [u8]) -> io::Result<Vec<Event>> {
    let n = unsafe { libc::read(fan_fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    let mut events = Vec::new();
    let mut offset = 0;
    while offset + mem::size_of::<EventMetadata>() <= n {
        let meta: EventMetadata =
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(offset).cast()) };
        if meta.vers != FANOTIFY_METADATA_VERSION
            || (meta.event_len as usize) < mem::size_of::<EventMetadata>()
        {
            break;
        }
        events.push(Event {
            mask: meta.mask,
            fd: meta.fd,
            pid: meta.pid,
        });
        offset += meta.event_len as usize;
    }
    Ok(events)
}

/// Answer a permission event. Must be called before closing `event.fd`.
pub fn respond(fan_fd: RawFd, event_fd: RawFd, allow: bool) -> io::Result<()> {
    let response = Response {
        fd: event_fd,
        response: if allow { FAN_ALLOW } else { FAN_DENY },
    };
    let ret = unsafe {
        libc::write(
            fan_fd,
            &response as *const Response as *const libc::c_void,
            mem::size_of::<Response>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

/// Wait for the fanotify fd to become readable; returns false on timeout.
pub fn wait_readable(fd: RawFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(ret > 0 && pollfd.revents & libc::POLLIN != 0)
}
