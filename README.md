# Kariba

> *Hold back the flood.*

A beautifully designed, open-source security suite for Linux that unifies
best-in-class security engines (ClamAV, YARA, rkhunter, AIDE, CrowdSec, Lynis,
…) behind one modern interface — daemon, CLI, and GUI.

Named after the Kariba Dam on the Zambezi river: the dam holds back the flood,
Kariba holds back the flood of threats.

**Status:** early development. See [PLAN.md](PLAN.md) for the full project
plan, architecture, and roadmap.

## Components

- `karibad` — root daemon: scanning orchestration, quarantine, IPC hub
- `kariba-cli` — headless client (status, survey, scan, quarantine)
- `kariba` — desktop GUI (Tauri 2 + Svelte 5) *(not yet scaffolded)*

## License

GPL-3.0 — see [LICENSE](LICENSE).
