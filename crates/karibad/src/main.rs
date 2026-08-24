mod broadcast;
mod db;
mod exclusions;
mod fanotify;
mod quarantine;
mod realtime;
mod scanner;
mod server;

use kariba_core::config::Settings;
use kariba_core::paths;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

fn main() {
    let socket = paths::socket_path();
    if socket.exists() {
        let _ = std::fs::remove_file(&socket);
    }

    let config_path = paths::config_path();
    let (settings, created) = match Settings::load_or_create(&config_path) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!(
                "karibad: cannot load config at {} ({e}); using in-memory defaults",
                config_path.display()
            );
            (Settings::default(), false)
        }
    };

    let db = match db::Db::open(&paths::db_path()) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("karibad: failed to open database: {e}");
            std::process::exit(1);
        }
    };

    let quarantine = match quarantine::Quarantine::new(paths::quarantine_dir()) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("karibad: failed to prepare quarantine dir: {e}");
            std::process::exit(1);
        }
    };

    let daemon = Arc::new(server::Daemon::new(
        db,
        quarantine,
        settings,
        config_path.clone(),
    ));
    daemon.sync_realtime();

    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("karibad: failed to bind {}: {e}", socket.display());
            std::process::exit(1);
        }
    };
    // Unprivileged clients (CLI/GUI) must be able to reach a root daemon —
    // same model as clamd's 0666 socket. polkit gates this in the packaging
    // phase; until then any local user can talk to karibad.
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666));

    println!(
        "karibad {} listening on {}",
        env!("CARGO_PKG_VERSION"),
        socket.display()
    );
    println!(
        "  config: {}{}",
        config_path.display(),
        if created {
            " (created with defaults)"
        } else {
            ""
        }
    );
    println!("  data dir: {}", paths::data_dir().display());
    let (realtime_active, realtime_detail) = daemon.realtime_status();
    println!(
        "  real-time: {} ({realtime_detail})",
        if realtime_active {
            "active"
        } else {
            "inactive"
        }
    );

    for stream in listener.incoming().flatten() {
        let daemon = Arc::clone(&daemon);
        std::thread::spawn(move || server::handle_connection(stream, daemon));
    }
}
