# AGENTS.md

Kariba: Linux security suite unifying external engines (currently ClamAV only) behind a root daemon + thin clients. Early development — `PLAN.md` is the canonical architecture doc; consult it before structural changes. Its workspace/layout diagrams are partly aspirational (e.g. `packaging/`, other engines don't exist yet).

## Commands

- `cargo test --workspace` — fast, no external services required
- Single test: `cargo test -p kariba-core expand_tilde`
- Lint: `cargo clippy --workspace`; format: `cargo fmt` (rustfmt.toml sets edition 2024)
- Run daemon: `cargo run -p karibad`; CLI: `cargo run -p kariba-cli -- survey|status|scan <paths> [--quarantine]|quarantine list|restore <id>|delete <id>`
- GUI: `cd apps/gui && pnpm install` first (lockfile is pnpm), then `pnpm tauri dev` (starts Vite itself on :1420) and `pnpm check` (svelte-check) for typechecking

## Architecture

- Cargo workspace, Rust edition 2024 (let-chains ok). Binaries: `karibad` (crates/karibad), `kariba-cli` (apps/cli), `kariba-gui` (apps/gui/src-tauri). Libraries: kariba-core, kariba-ipc, kariba-survey, kariba-engine-clamav (crates/engines/clamav).
- IPC is JSON-RPC 2.0 over a Unix socket. Method constants and shared param/result types live in `crates/kariba-ipc/src/protocol.rs` — daemon, CLI, and GUI must all use them. `scan.start` streams `scan.progress`/`scan.detection` notifications before the response arrives.
- Layering rules (from PLAN.md): kariba-core holds facts only (paths, distro/init detection), zero policy; kariba-survey adds policy (checks, advice; detects only, never auto-installs); engines depend on core, never on survey.
- GUI: Svelte 5 + Tailwind v4; all daemon access goes through Tauri commands in `apps/gui/src-tauri/src/main.rs`, wrapped in `apps/gui/src/lib/api.ts`. Scan progress reaches the frontend via Tauri events `kariba://scan-progress` / `kariba://scan-detection`. The window is frameless (`decorations: false`); `components/Titlebar.svelte` provides the drag region and window controls (needs `core:window:allow-start-dragging` etc. in `capabilities/default.json`). Bundle is intentionally disabled (`tauri.conf.json`).

## Gotchas

- Paths are privilege-dependent (`kariba_core::paths`): root uses `/run/kariba` + `/var/lib/kariba`, non-root falls back to `$XDG_RUNTIME_DIR` / `$XDG_DATA_HOME` / `~/.local/share/kariba`. Daemon and client must run as the same user or they use different socket paths.
- `karibad` must be running for everything except `kariba-cli survey`, which runs locally without the daemon.
- Real scans need a running `clamd`. Dev boxes: Artix/OpenRC (`clamav` + `clamav-openrc` separately) and Arch/systemd (plain `clamav`; enable `clamav-daemon.service` + `clamav-freshclam.service`). Socket `/run/clamav/clamd.ctl` on both. EICAR is the end-to-end detection test vector.
- To run `karibad` as root without creating root-owned files in `target/`, build as the user first (`cargo build -p karibad`), then `sudo ./target/debug/karibad`; run the CLI with the same privilege level or socket paths won't match.
- Quarantine invariants (tested in crates/karibad/src/quarantine.rs): quarantined files are mode 000, restore round-trips byte-identical. Don't weaken these.
- NVIDIA + Wayland crashes WebKitGTK at startup ("Gdk Protocol error 71") and XWayland renders a solid color there, so neither native DMABUF nor X11 fallback works on NVIDIA. `kariba-gui` auto-sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` when NVIDIA + Wayland is detected (`apply_nvidia_wayland_workaround` in apps/gui/src-tauri/src/main.rs); don't remove it without a replacement.
- PLAN.md "Known Issues / Follow-ups" lists accepted bugs (sequential scan throughput is the main one). Check there before diagnosing scan behavior as new. All GUI Tauri commands are async (`spawn_blocking`) and the scanner takes short-lived DB locks — keep it that way so the UI stays responsive mid-scan. `scan.cancel` plus dead-client detection (failed notification sends) abort scans server-side; don't reintroduce orphaned scans.
- Commits use Conventional Commits (`feat(cli):`, `fix(karibad):`, `docs:`); single `main` branch. No CI configured yet.
- `apps/gui/src-tauri/gen/schemas/` is generated and gitignored; never commit it.
