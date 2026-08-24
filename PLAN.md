# Kariba — Linux Security Suite

> *Hold back the flood.*

Named after the Kariba Dam on the Zambezi river — one of the largest dams in the
world. The dam holds back the flood; Kariba holds back the flood of threats.
Abstract product name (à la Sophos, ESET, Avast); the tagline carries the AV signal.

Repo: `FlowOSS/kariba` · License: GPL-3.0 · Stack: Rust + Tauri 2 + Svelte

> **Verification markers** — development happens on **Artix Linux (OpenRC)**.
> `[verified]` = tested on the dev machine. `[ASSUMPTION]` = believed true but
> **not yet verified**; these are collected in
> [Assumptions to Verify](#assumptions-to-verify) and get checked when we
> reach the relevant systems. Do not treat assumptions as facts.

---

## Overview

A beautifully designed, open-source security application for Linux that wraps
multiple best-in-class open-source security engines into a single, modern UI.
Fills the gap between ugly legacy tools (ClamTk) and expensive/discontinued
commercial solutions (ESET, Bitdefender, Sophos).

## Problem Statement

- Linux desktop users are growing rapidly, but security tooling is either:
  - Ugly and outdated (ClamTk)
  - Expensive and closed-source (ESET, Bitdefender — discontinued Linux support)
  - Command-line only (ClamAV, rkhunter, AIDE)
- New Linux users expect a "Windows-like" antivirus experience: dashboard,
  tray icon, one-click scan, quarantine manager.
- No unified solution exists that correlates multiple engines into one
  cohesive threat model with a modern GUI.

## Architecture

```
┌────────────────────────────────────────────────────────────────────────────┐
│                               USER SPACE                                   │
│                                                                            │
│    ┌─────────────────┐                    ┌─────────────────┐              │
│    │   kariba (GUI)  │                    │    kariba-cli   │              │
│    │ Tauri 2 + Svelte│                    │  headless ops   │              │
│    └────────┬────────┘                    └────────┬────────┘              │
│             │        Unix socket · JSON-RPC 2.0 + event stream             │
│             │        /run/kariba/karibad.sock  (polkit-gated)              │
│             ▼                                                              │
│    ┌─────────────────────────────────────────────────────────────┐         │
│    │                     karibad  (root)                         │         │
│    │   scheduler · quarantine · survey · correlator · IPC hub    │         │
│    └──┬─────────┬─────────┬─────────┬──────────┬─────────┬───────┘         │
│       ▼         ▼         ▼         ▼          ▼         ▼                 │
│   ┌───────┐ ┌───────┐ ┌────────┐ ┌──────┐ ┌────────┐ ┌────────┐            │
│   │ clamd │ │yara-x │ │rkhunter│ │ AIDE │ │CrowdSec│ │Tetragon│  …         │
│   │socket │ │in-proc│ │subproc │ │subpr.│ │  API   │ │ eBPF   │            │
│   └───────┘ └───────┘ └────────┘ └──────┘ └────────┘ └────────┘            │
│                                                                            │
│    SQLite /var/lib/kariba/kariba.db   Quarantine /var/lib/kariba/quar/     │
└────────────────────────────────────────────────────────────────────────────┘
                            │ fanotify (FAN_OPEN_EXEC_PERM)
                            ▼
                      ┌───────────┐
                      │  KERNEL   │  block execution · scan on write
                      └───────────┘
```

### Tech Stack

- **App shell**: Tauri 2 (Rust) — native webview, tray, notifications
- **Frontend**: Svelte 5 + Vite + TypeScript (details in UI Stack below)
- **Backend**: `karibad` — Rust daemon, runs as root; init-agnostic (see
  Service & Init Support below)
- **CLI**: `kariba-cli` for servers/headless use (same daemon)
- **Database**: SQLite via `rusqlite` (scans, threats, quarantine metadata)
- **IPC**: Unix domain socket + JSON-RPC 2.0 with server-pushed events
- **Notifications**: D-Bus desktop notifications
- **System tray**: StatusNotifierItem (works on both X11 and Wayland)
- **Privilege escalation**: polkit policy for GUI → daemon privileged calls

### UI Stack

| Layer | Choice | Why |
|-------|--------|-----|
| App shell | **Tauri 2** (Rust) | ~10MB resident binary, native tray/notifications, WebKitGTK webview. An always-on AV must be light — Electron idles at 300MB+, unacceptable. |
| Frontend | **Svelte 5 + Vite + TypeScript** | Runes give fine-grained reactivity with near-zero boilerplate; the framework compiles away; easiest to maintain for a small OSS team. |
| Styling | **Tailwind CSS v4** | Utility-first, CSS-first theming (`@theme` design tokens, oklch colors), <10kB shipped CSS. |
| Components | **shadcn-svelte** (+ bits-ui primitives) | Copy-in components you own outright (no library upgrade lock-in), modern look out of the box, accessible headless primitives, built-in charts. |
| Icons | **Lucide** (`lucide-svelte`) | Consistent modern stroke icons; same family shadcn designs against. |
| Charts | **LayerChart** | Svelte-native; scan history, threat trends, Lynis score over time. |
| Fonts | **Geist** + **JetBrains Mono** | Geist for UI (current, clean); mono for file paths and hashes. |
| Motion | `svelte/transition` + **motion** | Built-in transitions cover 90%; `motion` for anything fancier. |
| Tauri plugins | tray-icon (core), notification, autostart, single-instance, updater, window-state, dialog | All official, all trivial to wire. |

**Verified latest stable (2026-08-23):** Tauri **2.11.5** (2.x is the latest
stable line), Svelte **5.56.10**, Vite **8.2.2** (rolldown-based), Tailwind CSS
**4.3.3**, shadcn-svelte **1.5.0** (bits-ui **2.19.0**), Lucide **1.0.1**,
LayerChart **2.3.0**, motion **13.1.1**, TypeScript **7.0.2**, Geist **1.7.2**.
Rust side: rusqlite **0.40.2**, tokio **1.53.1**, serde **1.0.229**. Tauri
plugins all on 2.x stable (notification 2.3.3, autostart 2.5.1, single-instance
2.4.3, updater 2.10.1, window-state 2.4.1, dialog 2.7.2).

**Alternatives considered**

- **React 19 + shadcn/ui** — biggest ecosystem, but more boilerplate; Svelte wins
  on write/maintain speed at this app's size.
- **GTK4/libadwaita (gtk4-rs)** — truly native, but GNOME-only aesthetic, fights
  KDE, and custom "modern dashboard" styling is painful.
- **Electron** — rejected on memory footprint alone.
- **Iced / Slint / egui** (pure Rust) — promising, but styling flexibility and
  component ecosystem aren't there yet for a polished consumer dashboard.

### Filesystem Layout (FHS-compliant)

| Path | Purpose |
|------|---------|
| `/etc/kariba/kariba.toml` | System-wide daemon config |
| `/var/lib/kariba/kariba.db` | SQLite database |
| `/var/lib/kariba/quarantine/` | Quarantined files (mode 000, root-only) |
| `/run/kariba/karibad.sock` | IPC socket |
| `~/.config/kariba/` | Per-user UI preferences |

### Security Engines

| Engine | Purpose | Integration | Status |
|--------|---------|-------------|--------|
| **ClamAV** | Signature-based file scanning | `clamd` Unix socket | Core |
| **YARA (yara-x)** | Malware-family pattern matching | In-process (pure-Rust rewrite, no C deps) | Core |
| **rkhunter** | Rootkit/backdoor detection | Subprocess | Core |
| **AIDE** | File integrity monitoring | Subprocess | Core |
| **CrowdSec** | Community IDS/IPS, IP reputation | Local API | Core |
| **Lynis** | Security audit + scoring | Subprocess | Core |
| **Tetragon** (eBPF) | Runtime behavioral detection | gRPC/JSON events | Phase 3 differentiator |
| **LMD** | Web malware signatures | Subprocess | Optional |
| **chkrootkit** | Second-opinion rootkit scan | Subprocess | Optional |
| **Fail2ban** | Brute-force protection | Subprocess | Optional (CrowdSec covers most) |
| **Wazuh/OSSEC** | HIDS, log analysis | Agent | Optional/advanced |

### Cargo Workspace Layout

```
kariba/
├── apps/
│   ├── gui/              # Tauri 2 + Svelte frontend
│   └── cli/              # kariba-cli
├── crates/
│   ├── karibad/          # daemon binary
│   ├── kariba-core/      # shared types, threat model, config
│   ├── kariba-ipc/       # JSON-RPC protocol (client + server)
│   ├── kariba-survey/    # dependency verification & guided setup
│   └── engines/
│       ├── clamav/  ├── yara/  ├── rootkit/
│       ├── aide/    ├── crowdsec/  └── lynis/
└── packaging/            # init scripts (systemd [ASSUMPTION], OpenRC),
                          # polkit policies, deb/rpm specs
```

### Crate Responsibilities

- **kariba-core** — shared *facts and types*, zero policy: threat model,
  config, and host-detection primitives (distro from `/etc/os-release`, init
  system probes). These live here because several crates consume them:
  engines need per-distro socket paths, karibad needs init awareness, survey
  needs both.
- **kariba-survey** — *policy* on top of core's facts: per-engine checks
  (binary, socket, DB age, service, init script), status reports, and
  distro×init-aware install suggestions. Detects and advises; does not
  auto-install.
- **kariba-ipc** — JSON-RPC protocol shared by daemon, CLI, and GUI.
- **karibad** — orchestration: scan scheduler, quarantine, IPC server.
- **engines/\*** — one adapter per engine; depend on core, never on survey.

### Design Decisions (vs. naive approach)

1. **fanotify over inotify** for real-time protection. inotify only notifies
   *after* the fact; fanotify with `FAN_OPEN_EXEC_PERM` can **block execution
   of a malicious file before it runs**. Requires root (hence the daemon).
   inotify remains as fallback for ancient kernels.
2. **yara-x over libyara C bindings** — pure Rust, memory-safe, no `-sys`
   build headaches across distros.
3. **System quarantine, not `~/.kariba`** — threats found in root-owned paths
   must be movable by the daemon; quarantine lives in `/var/lib/kariba` with
   mode 000 files, owned by root.
4. **Daemon + thin clients** — GUI and CLI are stateless clients of `karibad`;
   protection keeps running whether the GUI is open or not.
5. **Native packaging only** — ship `.deb`, `.rpm`, AppImage. No Flatpak/Snap:
   sandboxing is fundamentally incompatible with a host-wide AV scanner, and
   the packaging adds no value here.

### Service & Init System Support

Kariba targets **systemd and non-systemd systems alike**. `karibad` is a plain
long-running process with no init-system dependency — any supervisor can run
it (or a user can run it in a terminal during development). What we ship in
`packaging/`:

| Init | Artifact | Status |
|------|----------|--------|
| systemd | `karibad.service` | `[ASSUMPTION]` — written, never run on a systemd system yet |
| OpenRC | `packaging/openrc/karibad` | developed and verified on Artix (dev machine) |
| runit / s6 / dinit | — | later, if demanded |

**Verified facts (Artix, 2026-08-23):**

- Artix splits init scripts into per-init packages: `clamav-openrc`,
  `clamav-runit`, `clamav-s6`, `clamav-dinit` (in `openrc-world`,
  `runit-world`, `s6-world`, `dinit-world` repos). Installing `clamav` alone
  provides **no** service management.
- The `clamd` OpenRC script (Gentoo lineage) also starts the freshclam daemon
  itself — gated by `START_FRESHCLAM` in `/etc/conf.d/clamd`. There is no
  separate `freshclam` service entry.
- clamd socket: `/run/clamav/clamd.ctl` (per `/etc/clamav/clamd.conf`);
  config lives in `/etc/clamav/`; DBs in `/var/lib/clamav/`.

**Verified facts (Arch Linux/systemd, 2026-08-23):**

- A single `clamav` package ships clamd, freshclam, **and** the systemd units
  — no separate init package needed (unlike Artix).
- Units: `clamav-daemon.service` (socket-activated via `clamav-daemon.socket`)
  and a separate `clamav-freshclam.service`. Confirms the systemd model:
  freshclam is its own service, not folded into the clamd script.
- clamd socket: `/run/clamav/clamd.ctl` (same as Artix), mode `0666`, owned
  by the `clamav` user — non-root clients (survey, karibad) can connect.
- First-time setup order matters: `sudo freshclam` **before** starting clamd
  (no DBs otherwise); the initial `Clamd was NOT notified` warning is expected.
- EICAR end-to-end re-verified on this box through karibad: detect (~37ms) →
  quarantine (mode 000) → restore byte-identical → delete.
- GUI gotcha on this box (Hyprland + NVIDIA RTX 5060 Ti): WebKitGTK
  crashed at startup with `Gdk Protocol error 71` (broken NVIDIA
  explicit-sync/DMA-BUF on Wayland), and the XWayland fallback renders a
  solid color on NVIDIA. Fixed in-app: kariba-gui auto-sets
  `WEBKIT_DISABLE_DMABUF_RENDERER=1` when NVIDIA + Wayland is detected
  (`apply_nvidia_wayland_workaround`, apps/gui/src-tauri/src/main.rs).
  User-visible workaround env vars (`WEBKIT_DISABLE_DMABUF_RENDERER=1`,
  `__NV_DISABLE_EXPLICIT_SYNC=1`) kept only as reference.

### Operational Notes: Signature DB Updates

1. **Reload coupling** — after freshclam updates the DBs it notifies clamd to
   reload. If clamd isn't running, freshclam logs `Clamd was NOT notified` and
   the new signatures only take effect once clamd (re)starts. Survey checks DB
   age; karibad should verify clamd actually picked up new DBs after updates.
2. **Init quirks** — how freshclam runs as a service differs per distro×init:
   Artix/OpenRC: inside the `clamd` script `[verified]`. systemd distros:
   separate `clamav-freshclam.service` `[verified on Arch 2026-08-23]`.
   Survey's service model must encode "which service provides freshclam" per
   target.
3. **No-service fallback** — some systems will have no freshclam automation at
   all (manual/cron only). Survey flags a stale `daily.cvd` (mtime older than
   N days) and advises.
4. **Future (post-MVP)** — karibad runs freshclam itself on schedule (it is
   already root): one unified "Update definitions" flow regardless of init
   system. MVP relies on the OS mechanism and only monitors it.
5. **YARA rules feed (Phase 2)** — yara-x ships no rules; signatures live in
   community feeds (Yara-Rules, Neo23x0/signature-base, vendor-published
   rules) with **mixed licenses** (parts CC-BY-NC or detection-use-only), so
   nothing can be bundled blindly. Kariba must play the role freshclam plays
   for ClamAV: feed manifest (URL/version/license), periodic fetch,
   compile-on-load, tiering (core packer rules always on, family rules
   optional), and resilience — a broken third-party rule must be skipped with
   a warning, never abort a scan.

## Real-time Protection Design

Decisions locked 2026-08-24 (threat-model review: "malware drops files
anywhere" + "AUR supply-chain hijack").

**Watch scope — mount-wide.** fanotify marks are per-mount, so karibad marks
each relevant local mount once rather than watching directories. Covered:
the root filesystem, `/home` and `/tmp` when separately mounted (tmpfs
included), and removable media as it appears. Never marked: pseudo
filesystems (proc, sysfs, devtmpfs, devpts, cgroup*, debugfs, securityfs,
tracefs, squashfs) and network filesystems (nfs, cifs, fuse.sshfs — scanning
remote bytes synchronously would hang local syscalls). Mounts are discovered
from `/proc/self/mountinfo`; the exclusions settings (already shipped) decide
what inside a marked mount is skipped.

**Events.** Two masks per mount:

- `FAN_OPEN_EXEC_PERM` — the exec gate. Synchronous: karibad must ALLOW or
  DENY before the execve completes. This is the security boundary — a
  detected payload is refused execution no matter where it landed.
- `FAN_CLOSE_WRITE` — scan-on-landing. Asynchronous: queued for scanning, no
  syscall is held. Detections feed the threats table, honor
  `realtime.auto_quarantine`, and broadcast to connected clients.

**Verdict policy — fail-open + re-scan.** Permission events hold the calling
process's syscall, so a slow verdict is user-visible. karibad bounds every
verdict (~2s): cache hit → instant; cache miss → engine scan within the
deadline; timeout or engine-down → ALLOW, queue a background re-scan, and
record it. Rationale: an AV that can hang every exec on the system is a
bigger liability than the residual race, and detection quality (not syscall
blocking) is where the actual protection comes from. clamd being down
degrades protection visibly in `status`/dashboard rather than silently.

**Verdict cache.** In-memory `(path, mtime, size) → verdict` so normal
exec/open churn doesn't round-trip to clamd. sha256 is computed only on
detection (threat records), keeping the hot path at stat + hashmap lookup.

**Privilege & degradation.** `FAN_CLASS_CONTENT` requires CAP_SYS_ADMIN: a
non-root dev daemon reports `realtime_active = false` with the reason and
never crashes. Root-mode testing uses `sudo ./target/debug/karibad` + CLI.
Interim GUI↔root-daemon access (until polkit lands with packaging): the
root daemon chmods its socket 0666 (clamd model) and unprivileged clients
fall back to `/run/kariba/karibad.sock` after trying their own, so the
user GUI reaches the root daemon — any local user can talk to karibad in
the meantime. If karibad dies, the kernel auto-allows pending permission
events (fail-open is kernel behavior, not a choice) — service supervision
with restart-on-crash is the mitigation.

**Engine I/O — INSTREAM, not paths.** karibad streams file *contents* to
clamd (`zINSTREAM`) instead of sending paths: the daemon runs as root and
can open anything, while clamd runs as the unprivileged `clamav` user,
which cannot traverse mode-700 home directories — path-based `SCAN`
silently misses every file in a private home (discovered in E2E testing
2026-08-24). Files beyond clamd's `StreamMaxLength` (default 25 MB) fall
back to path-based SCAN. INSTREAM responses are NUL-terminated, unlike
SCAN's newline-terminated replies.

**Known race.** Between close-write and its async verdict, a non-exec read
can touch a fresh file. Accepted: the exec gate closes the dangerous path
(files that merely get read can't run code), matching the minifilter model.

**Why our own watcher instead of ClamAV's `clamonacc`.** ClamAV ships an
optional on-access scanner (`clamonacc`, also fanotify-based), but it is a
separate process configured inside `clamd.conf` that only detects and logs —
no quarantine, no policy layer, no client feed. Building the fanotify
watcher inside karibad lets real-time protection obey Kariba settings
(master toggle, exclusions, auto-quarantine), act on detections (deny exec,
quarantine with mode 000), and broadcast verdicts to CLI/GUI over the
existing IPC.

## Features

### Core Features

1. **Real-time Protection**
   - fanotify permission events (`FAN_OPEN_EXEC_PERM`, `FAN_OPEN_PERM`)
   - Block execution / scan on create-modify-close
   - Auto-quarantine detected threats
   - Configurable exclusions (paths, file types, processes)
   - Catches files regardless of arrival vector (browser download, archive
     extraction, USB copy): everything lands on disk and passes fanotify.
     Encrypted archives are never decrypted — extracted files are scanned on
     landing, same model as Windows Defender's minifilter
   - Synchronous verdicts: permission events hold the syscall until karibad
     allows/denies, so scan latency is user-visible; needs a timeout policy
     (fail-open + background re-scan vs. deny)
   - **Watch scope (decided 2026-08-24): mount-wide from day 1.** fanotify
     marks are per-mount, so marking the root/home/tmp/removable mounts
     covers files dropped *anywhere* on those filesystems — not just
     `~/Downloads`. The exclusions settings are the knob that keeps this
     practical. Pseudo-FS (proc/sys/dev/cgroup/…) and network FS are never
     marked.
   - **Verdict policy (decided 2026-08-24): fail-open + re-scan.** A verdict
     is bounded (~2s); on timeout or engine-down karibad ALLOWS the syscall,
     queues a background re-scan, and alerts — the system never hangs on a
     slow engine. The exec gate + detection quality is the security boundary.
     A verdict cache (path+mtime+size → verdict) keeps the hot path cheap so
     normal exec/open traffic doesn't re-scan via clamd.
   - **Scope limit — what real-time does NOT solve:** build-time /
     supply-chain attacks (see the Supply-chain protection thread below).
     Scanning catches malicious *artifacts on disk*; it cannot stop a
     malicious build script from running legitimate tools with the user's own
     permissions.

2. **On-Demand Scanning**
   - Quick scan (`~/Downloads`, `/tmp`, `/var/tmp`)
   - Full scan (entire filesystem, parallel workers)
   - Custom scan (user-selected paths)
   - Archives (.zip, .tar, .gz, .7z) via ClamAV
   - Mounted drives / network shares (optional)
   - Smart-scan phases `[post-MVP]` — instead of one raw filesystem walk, run
     ordered stages with per-stage progress (Avast lineage): memory/process
     locations → autostart entries → home directories → full tree → archives.
     Needs engine-layer support for stage-aware scanning and a protocol
     extension to report the current phase in `scan.progress`.

3. **Scheduled Scans** — internal cron-like scheduler (no cron dependency),
   auto definition updates, optional scan-on-boot.

4. **Quarantine Management** — restore/delete/ignore, export/import for
   analysis, per-item threat details (engine, signature, SHA-256).

5. **Rootkit Detection** — periodic rkhunter runs, highlighted findings,
   guided remediation.

6. **File Integrity Monitoring** — AIDE baseline wizard, alerts on changes to
   `/usr/bin`, `/etc`, `/boot`, whitelist workflow for legitimate updates.

7. **Network Security** — CrowdSec community threat intel, automatic IP
   bans, blocked-connection log, optional Fail2ban status.

8. **System Security Audit** — Lynis run, 0-100 score, hardening
   recommendations, trend over time.

9. **Definition Updates** — auto/manual for ClamAV (freshclam), YARA rules
   (curated community feeds), LMD; update history log.

10. **System Tray** — StatusNotifierItem icon (green/yellow/red), quick
    actions, minimal idle footprint.

11. **CLI** — first-class headless experience:

```
$ kariba status
● protected · engines 5/5 · last scan 2h ago (0 threats)

$ kariba scan ~/Downloads --quarantine
scanned 12,204 files · 1 threat quarantined

$ kariba update && kariba scan --full
```

12. **Survey** — dependency verification & guided setup (named after the
    surveyors who verify ground before a dam is built):
    - Detects distro (`/etc/os-release`), package manager, and init system
      (systemd / OpenRC / runit / s6 / dinit probes)
    - Per-engine checks: binary present, daemon socket reachable, signature
      DB age, service running, init script installed
    - Distro×init-aware suggestions with exact install commands (e.g. Artix:
      `clamav` and `clamav-openrc` are separate packages)
    - Engines degrade gracefully: missing engine = "unavailable", never crash
    - Surfaces as `kariba-cli survey` now, GUI "Survey" view later

13. **Supply-chain Protection** `[thread added 2026-08-24]` — Linux malware
    increasingly arrives via hijacked package builds (e.g. orphaned AUR
    packages adopted by bad actors), not just dropped files. Real-time
    scanning catches malicious artifacts on disk but cannot stop a malicious
    build script running legitimate tools with the user's own permissions, so
    this threat gets its own layered thread:
    - **Build isolation** (most effective): build AUR/third-party packages in
      a clean chroot/container/VM (`devtools`-style), never directly on the
      host, so a hijacked `PKGBUILD` cannot touch the real system. Kariba's
      role: Survey-style check that warns when packages are being built
      directly on host, plus guided setup of an isolated builder.
    - **Provenance audit**: heuristic flags on AUR metadata — recently
      orphaned→adopted, recent maintainer change, low votes/last-modified
      anomalies. Reputation signal, not signatures; surfaced in Survey/GUI.
    - **File integrity monitoring** (Phase 2, AIDE): detects a package
      quietly modifying `/usr/bin/*` or `/etc` post-install.
    - **Behavioral detection** (Phase 3, Tetragon/eBPF): watches what
      processes *do* (unexpected network/writes during builds) — the
      living-off-the-land answer.
    - Honest scope: scanning is necessary but not sufficient here; isolation
      is the primary boundary.

### Advanced Features (Future)

- **Multi-engine correlation** — same hash flagged by 2+ engines ⇒ severity
  escalation + higher confidence.
- **eBPF behavioral detection** (Tetragon) — process/exec/network telemetry,
  heuristic detection without signatures.
- Cloud lookup (VirusTotal / hash reputation APIs)
- Bubblewrap micro-sandbox for detonating suspicious files
- Email scanning (postfix/sendmail milter)
- USB auto-scan, firewall GUI (UFW/firewalld wrapper)

## UI/UX Design

### Design Principles

1. **Non-intrusive** — quiet in background, minimal notifications
2. **One-click actions** — Quick Scan, Update, Pause from tray
3. **Visual status** — green = protected, yellow = warnings, red = threats
4. **Detailed but optional** — expand threat details for technical info
5. **Modern aesthetic** — clean, minimal, dark mode by default
6. **Accessible** — keyboard navigation, screen reader support

### ASCII Mockups

#### Logo

```
██╗  ██╗ █████╗ ██████╗ ██╗██████╗  █████╗
██║ ██╔╝██╔══██╗██╔══██╗██║██╔══██╗██╔══██╗
█████╔╝ ███████║██████╔╝██║██████╔╝███████║
██╔═██╗ ██╔══██║██╔══██╗██║██╔══██╗██╔══██║
██║  ██╗██║  ██║██║  ██║██║██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝
        H O L D   B A C K   T H E   F L O O D
```

#### Dashboard

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ◈ KARIBA                                                            ─ □ ✕   │
├──────────────────────────────────────────────────────────────────────────────┤
│  ● PROTECTED     Last scan 2h ago · 0 threats · security score 87/100        │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ╭─────────────────────────────╮  ╭──────────────────────────────────────╮   │
│  │  SYSTEM STATUS              │  │  QUICK ACTIONS                       │   │
│  │                             │  │                                      │   │
│  │        ◉  SECURE            │  │  [ Quick Scan ]    [ Full Scan ]     │   │
│  │        0 active threats     │  │  [ Custom Scan… ]  [ Update DBs  ]   │   │
│  │        Real-time: ON        │  │                                      │   │
│  │        Engines:   5/5 up    │  │  ⏻ Real-time protection      [ON ]   │   │
│  ╰─────────────────────────────╯  ╰──────────────────────────────────────╯   │
│                                                                              │
│  ╭─ ENGINE STATUS ────────────────────────────────────────────────────────╮  │
│  │  ClamAV     ● active    8.6M signatures     defs updated 3h ago        │  │
│  │  YARA       ● active    1,204 rules loaded                             │  │
│  │  rkhunter   ○ idle      last run 2h ago · clean                        │  │
│  │  AIDE       ● watching  41,302 files baselined                         │  │
│  │  CrowdSec   ● active    12 IPs banned (24h)                            │  │
│  ╰────────────────────────────────────────────────────────────────────────╯  │
│                                                                              │
│  ╭─ RECENT ACTIVITY ──────────────────────────────────────────────────────╮  │
│  │  14:02  ✓  Quick scan complete — 182,410 files, 0 threats              │  │
│  │  13:47  ⚠  Quarantined ~/Downloads/invoice.pdf.exe (ClamAV)            │  │
│  │  11:20  ✓  Virus definitions updated (freshclam)                       │  │
│  │  09:15  ●  CrowdSec banned 45.155.x.x — ssh brute-force                │  │
│  ╰────────────────────────────────────────────────────────────────────────╯  │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Scan View

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ◈ KARIBA · FULL SCAN                                                ● LIVE  │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ▸ /home/stikyt/.cache/thumbnails/large                                      │
│                                                                              │
│  ████████████████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  54%         │
│  812,334 files · 14.2k files/s · elapsed 07:03 · ETA 06:12                   │
│                                                                              │
│  ╭─ DETECTED (2) ─────────────────────────────────────────────────────────╮  │
│  │  ▲▲ HIGH   ~/Downloads/crack/keygen        ClamAV    Trojan.Agent      │  │
│  │  ▲  MED    /tmp/.hidden/payload.bin        YARA      packer_upx        │  │
│  ╰────────────────────────────────────────────────────────────────────────╯  │
│                                                                              │
│                             [ ⏸ Pause ]    [ ■ Stop ]                        │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Scan Results

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ◈ KARIBA · SCAN RESULTS                       Full Scan · 3 threats found   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────┬─────────────────────────────┬─────────┬─────────────┬────────────┐  │
│  │ SEV │ PATH                        │ ENGINE  │ SIGNATURE   │ ACTION     │  │
│  ├─────┼─────────────────────────────┼─────────┼─────────────┼────────────┤  │
│  │ ▲▲  │ ~/Downloads/keygen          │ ClamAV  │ Trojan.Agt  │ [Quarant.] │  │
│  │ ▲   │ /tmp/.h/payload.bin         │ YARA    │ packer_upx  │ [Quarant.] │  │
│  │ ●   │ ~/old/setup.exe             │ LMD     │ heuristic   │ [ Ignore ] │  │
│  └─────┴─────────────────────────────┴─────────┴─────────────┴────────────┘  │
│                                                                              │
│  Selected: ~/Downloads/keygen                                                │
│  ╭─ DETAILS ──────────────────────────────────────────────────────────────╮  │
│  │  SHA-256   3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b99…   │  │
│  │  Size      214 KB          First seen   2026-08-23 13:47               │  │
│  │  Engines   ClamAV ✓  YARA ✓   (2/2 agree → confidence HIGH)            │  │
│  ╰────────────────────────────────────────────────────────────────────────╯  │
│                                                                              │
│            [ Quarantine All ]      [ Delete ]      [ Ignore ]                │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Quarantine

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ◈ KARIBA · QUARANTINE                                       3 items · 1.2 MB│
├──────────────────────────────────────────────────────────────────────────────┤
│  Filter: [ All ▾ ]  [ Any severity ▾ ]  [ Any engine ▾ ]     🔍 search…      │
│                                                                              │
│  ┌──────────────────────────────┬────────────┬──────────┬─────────────────┐  │
│  │ ORIGINAL PATH                │ QUARANTINED│ ENGINE   │ ACTIONS         │  │
│  ├──────────────────────────────┼────────────┼──────────┼─────────────────┤  │
│  │ ~/Downloads/keygen           │ 2h ago     │ ClamAV   │ [Restore] [Del] │  │
│  │ /tmp/.h/payload.bin          │ 2h ago     │ YARA     │ [Restore] [Del] │  │
│  │ ~/old/setup.exe              │ 3d ago     │ LMD      │ [Restore] [Del] │  │
│  └──────────────────────────────┴────────────┴──────────┴─────────────────┘  │
│                                                                              │
│  ⓘ Quarantined files are stored mode 000 under /var/lib/kariba/quarantine    │
│    and cannot be executed. Export selected items for offline analysis.       │
│                                                                              │
│                        [ Export… ]      [ Delete permanently ]               │
└──────────────────────────────────────────────────────────────────────────────┘
```

#### Settings

Implemented 2026-08-24. Users must always be able to see and change what
Kariba does — including turning protection off — so the settings layer was
built before real-time protection lands. The real-time master toggle ships
now and persists intent; the fanotify slice reads it.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  ◈ KARIBA · SETTINGS                                                         │
├────────────────┬─────────────────────────────────────────────────────────────┤
│  Dashboard     │  PROTECTION                                                 │
│  Scan          │                                                             │
│  Quarantine    │   Real-time protection                       [ON ]          │
│  Survey        │   Watch files as they land and gate execution of threats.   │
│                │   Takes effect once real-time scanning is active.           │
│  ──────────    │                                                             │
│ ▸ Settings     │   Auto-quarantine detections                 [ON ]          │
│                │   Move threats to quarantine automatically on detection.    │
│                │                                                             │
│                │  SCANNING                                                   │
│                │                                                             │
│                │   Quarantine threats by default              [ON ]          │
│                │   Applies to scans started without an explicit choice.      │
│                │                                                             │
│                │  EXCLUSIONS                                                 │
│                │                                                             │
│                │   Paths never scanned:                       [ + Add path ] │
│                │     /proc            ◆ built-in                  ✕          │
│                │     /sys             ◆ built-in                  ✕          │
│                │     /dev             ◆ built-in                  ✕          │
│                │     /run             ◆ built-in                  ✕          │
│                │     /home/stikyt/vms                             ✕          │
│                │                                                             │
│                │   File types skipped:                   [ + Add pattern ]   │
│                │     *.iso  ✕     *.img  ✕                                   │
└────────────────┴─────────────────────────────────────────────────────────────┘
```

Interactions (all implemented):

- Toggling real-time protection **off** shows a one-click confirm dialog
  ("Turn off protection?" → Cancel / Turn off). Friction, not lockout —
  the user's machine, the user's call.
- Built-in exclusions (`/proc`, `/sys`, `/dev`, `/run`) are badged ◆ and
  user-removable, but removal shows a scary warning explaining the
  consequence per path (kernel pseudo-files can stall the scan engine,
  device nodes can hang reads).
- When ≥1 built-in is missing, a persistent warning banner appears with a
  **Restore built-ins** button that re-adds only the missing ones.
- The quarantine directory itself is always skipped structurally (not a
  setting — scanning quarantined blobs would re-detect them).
- Dashboard shows "Protection off / Settings ▸ to re-enable" when disabled.

**Config schema** — TOML, owned by the daemon, at `/etc/kariba/kariba.toml`
(root) or `~/.config/kariba/kariba.toml` (unprivileged dev mode). Created
with defaults on first daemon start; `settings.set` validates, persists
atomically (tmp + rename), then applies. Missing keys fall back to
defaults, so hand-edited partial files work.

```toml
[realtime]
enabled = true            # master switch; fanotify slice reads this
auto_quarantine = true

[scan]
default_quarantine = true # applies when a client sends no explicit choice

[exclusions]
paths = ["/proc", "/sys", "/dev", "/run"]   # prefix match
extensions = []                              # "*.iso" patterns, case-insensitive
```

**RPC** — `settings.get` returns the whole document; `settings.set` accepts
the whole document (read-modify-write clients; no partial-update semantics).
Validation: exclusion paths must be absolute or `~/…`; extension patterns
normalize to `*.ext`. `status` carries `protection_enabled` so any client
can show protection state. CLI parity: `kariba-cli settings`,
`settings set <key> <value>` (dotted keys), `settings restore-builtins`.

#### System Tray

```
                                      ┌──────────────────────────────────────┐
      ● (green shield)                │  ◈ Kariba — Protected                │
                                      │  Last scan 14:02 · 0 threats         │
                                      ├──────────────────────────────────────┤
                                      │  Quick Scan                          │
                                      │  Full Scan                           │
                                      │  Update definitions                  │
                                      ├──────────────────────────────────────┤
                                      │  Pause protection                ▸   │
                                      ├──────────────────────────────────────┤
                                      │  Open Kariba                         │
                                      │  Quit                                │
                                      └──────────────────────────────────────┘
```

## Implementation Plan

### Phase 1: MVP (2-3 months)

1. **Project Setup** — cargo workspace, Tauri 2 scaffold, `karibad` skeleton,
   JSON-RPC IPC protocol, SQLite schema.
2. **Core Scanning** — clamd integration (quick/full/custom), parallel
   filesystem walk, results UI.
3. **Quarantine** — move to `/var/lib/kariba/quarantine`, mode 000, metadata
   in SQLite, restore/delete/export.
4. **Real-time Protection** — fanotify watcher, mount-wide marks (root,
   `/home`, `/tmp`, removable on mount); exec gate (`FAN_OPEN_EXEC_PERM`) +
   scan-on-close (`FAN_CLOSE_WRITE`), verdict cache, fail-open timeout
   policy, auto-quarantine on detection, live `realtime.enabled` toggle.
5. **System Tray + Basic UI** — status icon, dashboard, scan view, results,
   settings (real-time toggle, exclusions).

**Exit criteria:** EICAR test file detected on download, blocked from
execution, and auto-quarantined — on the dev machine (Artix/OpenRC).
`[verified 2026-08-24]` via the real-time watcher: landing detection,
exec-gate denial, and auto-quarantine all demonstrated end-to-end.
Ubuntu (deb) / Fedora (rpm) verification is deferred `[ASSUMPTION]` — see
Assumptions to Verify.

### Phase 2: Advanced Engines (2-3 months)

6. **yara-x integration** — rule loading, scan alongside ClamAV,
   engine-specific results. Includes the **rules-feed layer**: yara-x is
   engine-only (no freshclam equivalent exists — see Operational Notes §5),
   so Kariba aggregates community feeds, curates for license/quality, and
   fetches/versions/compiles them on load.
7. **Rootkit detection** — rkhunter scheduling + remediation guide.
8. **File integrity monitoring** — AIDE baseline wizard, periodic checks,
   alerts with whitelist workflow.
9. **Network security** — CrowdSec integration, banned-IP view, optional
   Fail2ban status.
10. **Scheduler + updates** — internal scheduler, auto definition updates,
    scan-on-boot, polkit policy for privileged calls.

### Phase 3: Polish & Launch (2-3 months)

11. **Lynis integration** — audit, score, recommendations.
12. **eBPF behavioral detection** — Tetragon integration, runtime telemetry
    surfaced in the activity feed (the differentiator).
13. **UI/UX polish** — animations, keyboard shortcuts, a11y audit, themes.
14. **Performance** — parallel scanning, backpressure-aware IPC progress,
    lazy UI loading.
15. **Packaging & docs** — .deb/.rpm/AppImage, init scripts (systemd
    `[ASSUMPTION]`, OpenRC), polkit configs, user guide, contribution guide.
16. **Launch** — GitHub release, r/linux, Hacker News, distro subreddits.

## Technical Challenges

1. **ClamAV integration** — `clamd` Unix socket (`INSTREAM`/`SCAN`),
   `freshclam` for updates, careful permission handling on quarantine.
2. **Real-time monitoring** — fanotify needs root (solved: root daemon);
   watch limits; balance coverage vs. performance; inotify fallback.
   Permission events hold the syscall, so verdicts must be fast (bounded
   scan latency + timeout policy); there is a small race between
   close-write and verdict where a non-exec read can touch a file — the
   exec gate closes the dangerous path. If karibad dies, the kernel
   auto-allows pending events (fail-open is kernel behavior, not a choice),
   so service supervision with restart-on-crash is the mitigation. MVP
   watches `~/Downloads` + `/tmp`; fanotify marks are per-mount, so
   expanding to system-wide is a scaling/config question, not an
   architecture change.
3. **File integrity** — large AIDE DB, handling legitimate system updates,
   false-positive whitelist workflow.
4. **Cross-distro compatibility** — package names, service names, and socket
   paths differ per distro×init (verified example: Artix needs `clamav` +
   `clamav-openrc` separately, the service is `clamd`, and freshclam rides
   inside its script). Survey encodes this as a data-driven mapping table;
   all non-Artix entries are `[ASSUMPTION]` until verified.
5. **Performance** — scanning 1M+ files without freezing UI; worker threads;
   batched IPC progress events.
6. **Quarantine safety** — no accidental execution (mode 000, root-owned),
   setuid/capability files, encrypted-at-rest option.
7. **Self-security** — a root daemon is a high-value target: memory-safe Rust,
   minimal IPC surface, fuzz the protocol, never shell out with interpolated
   user input, signed definition updates where engines support it.

## Known Issues / Follow-ups

Exposed during GUI testing (2026-08-23) — fix before alpha:

1. **Sequential scan throughput** — ~60 files/s on `/usr` (single clamd
   connection, one round-trip per file). Phase 3 parallel scanning (worker
   pool + multiple clamd connections or `INSTREAM` batching) addresses this.
2. **Real-time catch awareness** — detections now surface in Quarantine
   (marked "caught in real time", auto-refresh on arrival) with an unread
   dot on the sidebar tab; the Dashboard status card no longer carries a
   detection list. Still open: desktop notifications and a system tray for
   when the GUI is closed or unfocused.

Resolved (2026-08-23): DB lock held for whole scan (scanner now takes
short-lived locks per DB operation; GUI commands are async, so status /
quarantine stay responsive mid-scan). Orphaned scans + no cancellation
(`scan.cancel` implemented with a per-scan cancel flag; failed notification
sends on a dead client connection now also cancel the scan, so disconnected
clients no longer leave scans running).

## Testing Strategy

- **EICAR** end-to-end tests through the real detection pipeline
- Integration tests against a mock `clamd` socket
- Property tests for quarantine invariants (permissions never exceed 000,
  restore round-trips byte-identical)
- CI: GitHub Actions — build, `clippy`, `cargo test`, package smoke tests in
  Ubuntu + Fedora containers

## Monetization (Optional)

Core stays open-source (GPL-3.0). Possible revenue:

1. **Premium features** — cloud hash lookup, centralized business management
2. **Donations** — GitHub Sponsors, Open Collective
3. **Enterprise support** — priority fixes, custom YARA rules, deployment
   consulting

## Competitors

| Product | Pros | Cons |
|---------|------|------|
| ClamTk | Free, open-source | Ugly, outdated, slow |
| ESET NOD32 | Good detection | Expensive, closed-source |
| Bitdefender | Good detection | Expensive, Linux support discontinued |
| Sophos | Was good | Discontinued |
| Comodo | Free | Poor detection, closed-source |
| **Kariba (this project)** | Free, open-source, modern UI, multi-engine correlation, eBPF roadmap | New, needs community trust |

## Name

**Kariba** — after the Kariba Dam, one of the world's largest. The dam holds
back the flood; Kariba holds back the flood of threats. Tagline:
*"Hold back the flood."* Availability verified 2026-08-23: crates.io and PyPI
names free; no conflicting security product; GitHub org handled by
`FlowOSS` (repo `FlowOSS/kariba`).

## Next Steps

1. ~~Choose a name~~ → **Kariba** ✓
2. Dev environment setup ✓ (Artix: `clamav` + `clamav-openrc`, freshclam DBs
   downloaded, clamd running, `clamdscan` sanity check passed; Arch/systemd:
   plain `clamav`, freshclam DBs, `clamav-daemon.service` +
   `clamav-freshclam.service` enabled, EICAR round-trip re-verified
   2026-08-23)
3. Scaffold cargo workspace ✓ (local git, Conventional Commits)
4. `kariba-core` + `kariba-survey` ✓ (distro×init detection, ClamAV checks)
5. `karibad` skeleton + JSON-RPC IPC + SQLite schema ✓
6. `engines/clamav` (clamd socket client) + quarantine (mode 000) ✓
7. `kariba-cli status|survey|scan|quarantine` + EICAR end-to-end proof ✓
   (EICAR detected ~20ms → quarantined mode 000 → restored byte-identical →
   deleted; verified 2026-08-23 on Artix dev machine)
8. ~~GUI~~ ✓ — Tauri 2 + Svelte 5: dashboard, scan (cancel + history),
   quarantine, survey, settings; frameless window, NVIDIA+Wayland workaround
9. ~~Settings layer~~ ✓ (2026-08-24) — daemon-owned TOML config,
   `settings.get`/`settings.set` RPC, GUI settings page with protection
   toggles + exclusion manager, CLI parity. Real-time master toggle ships
   ahead of the fanotify slice so users can opt out before it exists.
10. ~~Real-time protection~~ ✓ (2026-08-24) — fanotify watcher, mount-wide
    marks, exec gate + scan-on-close, verdict cache, fail-open policy, live
    `realtime.enabled` toggle, INSTREAM scanning (mode-700 homes covered),
    GUI live-detection feed. E2E verified on the Artix dev box: EICAR write
    detected on landing (respecting `auto_quarantine`), exec attempt denied
    by the gate (`Operation not permitted`, exit 126), re-enabled
    auto-quarantine moved the file on the next blocked exec.
11. Packaging: systemd unit `[ASSUMPTION]` + OpenRC script
12. Push to `FlowOSS/kariba`, alpha release for community feedback

**Versioning.** Kariba follows semver strictly. Everything pre-release lives
in `0.x`: the current state is not yet worthy of a shipped build, so the
workspace sits at `0.0.1` (development-only, never released). First public
builds use prerelease tags (`0.1.0-alpha.1`, `0.1.0-beta.1`); plain
`0.1.0` lands only when there is an MVP actually worth testing. Packaging
(item 11) is deliberately deferred until that point.

## Assumptions to Verify

Everything marked `[ASSUMPTION]` in this document, collected for later
checking. Development happens on Artix (OpenRC) and Arch Linux (systemd);
verify these when we reach the relevant systems:

- [x] systemd distros: ClamAV service unit names (`clamav-daemon.service`,
      `clamav-freshclam.service` as a separate unit) — Arch-systemd
      `[verified 2026-08-23]` (plus socket-activated `clamav-daemon.socket`);
      Debian, Fedora still open
- [ ] systemd: our `karibad.service` works (socket path lifecycle, restart
      behavior, hardening options)
- [x] clamd socket default paths: `/run/clamav/clamd.ctl` verified on both
      Artix `[verified]` and Arch Linux `[verified 2026-08-23]`; Debian may
      differ, e.g. `/var/run/clamav/clamd.ctl`
- [ ] package names per distro family for Survey suggestions (Arch/systemd:
      plain `clamav` `[verified 2026-08-23]`; Debian/Ubuntu, Fedora,
      openSUSE still open)
- [ ] CrowdSec / Lynis / rkhunter / AIDE packaging and service names per
  distro
- [ ] YARA rules feeds: license terms for Yara-Rules / Neo23x0
  signature-base / vendor-published rules, and which redistribution-clean
  subset can be bundled vs. must be fetched at runtime
- [ ] polkit agent availability/behavior across desktops (KDE/GNOME/Xfce)
- [ ] fanotify: raw-libc bindings vs. a mature crate; FAN_OPEN_EXEC_PERM
      needs kernel ≥5.0; tmpfs `/tmp` marks; btrfs subvolume coverage
      (one mark per mount should cover subvolumes); event throughput on a
      busy desktop
- [ ] AUR provenance audit: which metadata (orphaned/adopted dates,
      maintainer history, votes) the AUR RPC actually exposes
- [ ] Phase 1 exit criteria on Ubuntu (deb) and Fedora (rpm)

## Resources

- [Tauri 2 Documentation](https://tauri.app/)
- [ClamAV Documentation](https://docs.clamav.net/)
- [yara-x (Rust YARA)](https://virustotal.github.io/yara-x/)
- [rkhunter](http://rkhunter.sourceforge.net/)
- [AIDE](https://aide.github.io/)
- [CrowdSec](https://www.crowdsec.net/)
- [Lynis](https://cisofy.com/lynis/)
- [Tetragon (eBPF)](https://tetragon.io/)
- [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html)
- [System Tray Icon](https://docs.rs/tray-icon/latest/tray_icon/)
