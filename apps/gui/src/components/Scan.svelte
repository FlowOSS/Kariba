<script lang="ts">
  import {
    Zap,
    Globe,
    FolderSearch,
    Play,
    Square,
    ScanSearch,
    ShieldCheck,
    ShieldAlert,
    ShieldOff,
    Archive,
  } from "@lucide/svelte";
  import * as api from "../lib/api";
  import { fmtDur, fmtRel } from "../lib/format";
  import type {
    Detection,
    ScanHistoryItem,
    ScanKind,
    ScanProgress,
    ScanResult,
    View,
  } from "../lib/types";

  let {
    preset = [],
    onnavigate,
  }: { preset?: string[]; onnavigate: (v: View) => void } = $props();

  const PRESETS: Record<ScanKind, string[]> = {
    quick: ["~/Downloads", "/tmp", "/var/tmp"],
    full: ["/"],
    custom: [],
  };

  const TYPES: { id: ScanKind; name: string; desc: string; icon: typeof Zap }[] = [
    { id: "quick", name: "Quick", desc: "Downloads, /tmp — fast", icon: Zap },
    { id: "full", name: "Full", desc: "Entire filesystem", icon: Globe },
    { id: "custom", name: "Custom", desc: "Choose your own paths", icon: FolderSearch },
  ];

  let kind = $state<ScanKind>("quick");
  let customPaths = $state("~/Downloads");
  let quarantine = $state(true);
  let running = $state(false);
  let done = $state(false);
  let cancelled = $state(false);
  let progress = $state<ScanProgress | null>(null);
  let detections = $state<Detection[]>([]);
  let result = $state<ScanResult | null>(null);
  let error = $state<string | null>(null);
  let history = $state<ScanHistoryItem[]>([]);
  let scanId = $state<number | null>(null);
  let startedAt = $state(0);
  let now = $state(0);

  $effect(() => {
    if (preset.length === 0) return;
    const joined = preset.join(",");
    if (joined === PRESETS.quick.join(",")) {
      kind = "quick";
    } else if (joined === PRESETS.full.join(",")) {
      kind = "full";
    } else {
      kind = "custom";
      customPaths = preset.join("\n");
    }
  });

  $effect(() => {
    if (!running) return;
    const timer = setInterval(() => (now = Date.now()), 1000);
    return () => clearInterval(timer);
  });

  let elapsedSecs = $derived(
    running || done ? Math.max(0, Math.floor(((now || Date.now()) - startedAt) / 1000)) : 0,
  );
  let pct = $derived(
    progress && progress.files_total > 0
      ? Math.min(100, (progress.files_scanned / progress.files_total) * 100)
      : 0,
  );
  let etaSecs = $derived(
    running && progress && elapsedSecs > 0 && progress.files_total > progress.files_scanned
      ? Math.round(
          ((progress.files_total - progress.files_scanned) * elapsedSecs) /
            progress.files_scanned || 0,
        )
      : null,
  );

  async function loadHistory() {
    try {
      history = await api.scanHistory();
    } catch {
      history = [];
    }
  }
  loadHistory();

  function severity(sig: string): "high" | "med" | "low" {
    const s = sig.toLowerCase();
    if (/trojan|ransom|rootkit|backdoor|worm|exploit/.test(s)) return "high";
    if (/test|eicar|pua|pup|adware|heuristic/.test(s)) return "low";
    return "med";
  }
  function sevGlyph(sig: string): string {
    const s = severity(sig);
    return s === "high" ? "▲▲" : s === "med" ? "▲" : "●";
  }
  function sevColor(sig: string): string {
    const s = severity(sig);
    return s === "high" ? "text-danger" : s === "med" ? "text-warn" : "text-muted";
  }
  function statusColor(status: string): string {
    if (status === "completed") return "text-ok";
    if (status === "cancelled") return "text-warn";
    if (status === "error") return "text-danger";
    return "text-accent";
  }

  async function start() {
    const paths =
      kind === "custom"
        ? customPaths
            .split(/[\n,]+/)
            .map((p) => p.trim())
            .filter(Boolean)
        : PRESETS[kind];
    if (paths.length === 0 || running) return;

    running = true;
    done = false;
    cancelled = false;
    result = null;
    error = null;
    detections = [];
    progress = null;
    scanId = null;
    startedAt = Date.now();
    now = startedAt;

    const unProgress = await api.onScanProgress((p) => {
      progress = p;
      scanId ??= p.scan_id;
    });
    const unDetection = await api.onScanDetection((d) => (detections = [...detections, d]));

    try {
      result = await api.scan(paths, quarantine, kind);
    } catch (e) {
      error = String(e);
    } finally {
      unProgress();
      unDetection();
      running = false;
      done = true;
      loadHistory();
    }
  }

  async function cancel() {
    cancelled = true;
    if (scanId != null) {
      try {
        await api.scanCancel(scanId);
      } catch {
        // best effort — the scan may have just finished
      }
    }
  }
</script>

<div class="mx-auto max-w-5xl px-8 py-8">
  <div class="mb-6">
    <h1 class="text-xl font-semibold">Scan</h1>
    <p class="text-sm text-muted">On-demand scanning via karibad → ClamAV</p>
  </div>

  <div class="mb-6 grid grid-cols-3 gap-4">
    <div class="card col-span-1 p-5">
      <div class="label mb-3">Scan type</div>
      <div class="flex flex-col gap-1">
        {#each TYPES as { id, name, desc, icon: Icon } (id)}
          <button
            class="w-full cursor-pointer rounded-lg px-3 py-2.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-40 {kind ===
            id
              ? 'bg-surface-2 text-ink'
              : 'text-muted hover:bg-surface-2/60 hover:text-ink'}"
            onclick={() => (kind = id)}
            disabled={running}
          >
            <div class="flex items-center gap-2 text-sm font-medium">
              <Icon size={15} /> {name}
            </div>
            <div class="mt-0.5 pl-6 text-xs text-muted">{desc}</div>
          </button>
        {/each}
      </div>

      {#if kind === "custom"}
        <textarea
          class="mt-3 h-24 w-full resize-none rounded-lg border border-edge bg-bg p-3 font-mono text-xs outline-none focus:border-accent disabled:opacity-40"
          placeholder="One path per line"
          bind:value={customPaths}
          disabled={running}
          spellcheck="false"
        ></textarea>
      {/if}

      <div class="label mt-5 mb-3">Options</div>
      <label class="flex cursor-pointer items-center gap-2.5 text-sm text-muted">
        <input
          type="checkbox"
          bind:checked={quarantine}
          disabled={running}
          class="accent-(--color-accent)"
        />
        Quarantine threats
      </label>

      <div class="mt-5">
        {#if running}
          <button class="btn btn-danger w-full justify-center" onclick={cancel}>
            <Square size={12} /> Cancel scan
          </button>
        {:else}
          <button class="btn btn-primary w-full justify-center" onclick={start}>
            <Play size={14} /> Start scan
          </button>
        {/if}
      </div>
    </div>

    <div class="col-span-2">
      {#if running}
        <div class="card p-6">
          <div class="mb-4 flex items-center justify-between">
            <div class="label">{kind} scan</div>
            <div class="flex items-center gap-2 text-xs text-accent">
              <span class="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-accent"></span>
              scanning
            </div>
          </div>

          <div class="mb-3 truncate font-mono text-xs text-muted">
            {progress?.current || "Beginning scan…"}
          </div>

          <div class="mb-3 h-1.5 overflow-hidden rounded-full bg-surface-2">
            {#if progress && progress.files_total > 0 && progress.files_scanned > 0}
              <div
                class="h-full rounded-full bg-accent transition-[width] duration-300 ease-out"
                style="width: {pct}%"
              ></div>
            {:else}
              <div
                class="h-full w-1/3 rounded-full bg-accent"
                style="animation: slide 1.2s ease-in-out infinite"
              ></div>
            {/if}
          </div>

          <div class="flex items-center justify-between font-mono text-xs text-muted">
            <span>
              {#if progress && progress.files_total > 0}
                {progress.files_scanned.toLocaleString()} /
                {progress.files_total.toLocaleString()} files
              {:else}
                enumerating files…
              {/if}
            </span>
            <span>
              {#if progress && progress.threats_found > 0}
                <span class="text-warn">{progress.threats_found} threat(s)</span> ·
              {/if}
              {fmtDur(elapsedSecs)}{#if etaSecs != null} · ETA {fmtDur(etaSecs)}{/if}
            </span>
          </div>

          {#if detections.length > 0}
            <div class="mt-5 border-t border-edge pt-4">
              <div class="label mb-3">Detected ({detections.length})</div>
              <div class="space-y-2">
                {#each detections as d (d.path + d.signature)}
                  <div class="flex items-center gap-3 text-sm">
                    <span class="shrink-0 text-xs {sevColor(d.signature)}"
                      >{sevGlyph(d.signature)}</span
                    >
                    <span class="truncate font-mono text-xs">{d.path}</span>
                    <span class="ml-auto shrink-0 text-xs text-muted">
                      {d.signature} · {quarantine ? "quarantined" : "detected"}
                    </span>
                  </div>
                {/each}
              </div>
            </div>
          {/if}
        </div>
      {:else if done && error}
        <div class="card flex items-start gap-3 border-danger/40 bg-danger/5 p-5">
          <ShieldOff size={20} class="mt-0.5 shrink-0 text-danger" />
          <div>
            <div class="font-medium text-danger">Scan failed</div>
            <div class="mt-1 text-sm text-muted">{error}</div>
          </div>
        </div>
      {:else if done && result}
        {#if cancelled}
          <div class="card mb-4 flex items-start gap-3 border-warn/40 bg-warn/5 p-5">
            <ShieldAlert size={20} class="mt-0.5 shrink-0 text-warn" />
            <div>
              <div class="font-medium text-warn">Scan cancelled</div>
              <div class="mt-1 text-sm text-muted">
                {kind} scan · {result.files_scanned.toLocaleString()} files before stopping
              </div>
            </div>
          </div>
        {:else if result.threats_found > 0}
          <div class="card mb-4 flex items-start gap-3 border-danger/40 bg-danger/5 p-5">
            <ShieldAlert size={20} class="mt-0.5 shrink-0 text-danger" />
            <div>
              <div class="font-medium text-danger">
                {result.threats_found} threat(s) found
              </div>
              <div class="mt-1 text-sm text-muted">
                {kind} scan · {result.files_scanned.toLocaleString()} files ·
                {Math.round(result.duration_ms / 1000)}s
                {#if result.quarantined > 0}· {result.quarantined} quarantined{/if}
              </div>
            </div>
          </div>
        {:else}
          <div class="card mb-4 flex items-start gap-3 border-ok/30 bg-ok/5 p-5">
            <ShieldCheck size={20} class="mt-0.5 shrink-0 text-ok" />
            <div>
              <div class="font-medium text-ok">No threats found</div>
              <div class="mt-1 text-sm text-muted">
                {kind} scan · {result.files_scanned.toLocaleString()} files ·
                {Math.round(result.duration_ms / 1000)}s
              </div>
            </div>
          </div>
        {/if}

        {#if detections.length > 0}
          <div class="card mb-4 overflow-hidden">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-edge text-left text-xs text-muted">
                  <th class="px-5 py-3 font-medium">SEV</th>
                  <th class="px-5 py-3 font-medium">Path</th>
                  <th class="px-5 py-3 font-medium">Signature</th>
                  <th class="px-5 py-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {#each detections as d (d.path + d.signature)}
                  <tr class="border-b border-edge/50 last:border-0">
                    <td class="px-5 py-3 text-xs {sevColor(d.signature)}">
                      {sevGlyph(d.signature)}
                    </td>
                    <td
                      class="max-w-64 truncate px-5 py-3 font-mono text-xs"
                      title={d.path}
                    >
                      {d.path}
                    </td>
                    <td class="px-5 py-3 text-xs">
                      {d.signature} <span class="text-muted">· {d.engine}</span>
                    </td>
                    <td class="px-5 py-3 text-xs text-muted">
                      {quarantine ? "quarantined" : "detected"}
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}

        <div class="flex gap-3">
          <button class="btn btn-primary" onclick={start}>
            <Play size={14} /> Scan again
          </button>
          {#if result.threats_found > 0 && quarantine}
            <button class="btn btn-ghost" onclick={() => onnavigate("quarantine")}>
              <Archive size={14} /> View quarantine
            </button>
          {/if}
        </div>
      {:else}
        <div class="card flex h-full flex-col items-center justify-center gap-3 p-10 text-muted">
          <ScanSearch size={32} class="opacity-40" />
          <div class="text-sm">Choose a scan type and start</div>
        </div>
      {/if}
    </div>
  </div>

  <div class="card overflow-hidden">
    <div class="label border-b border-edge px-5 py-3">Recent scans</div>
    {#if history.length === 0}
      <div class="flex flex-col items-center gap-3 py-10 text-muted">
        <ScanSearch size={24} class="opacity-40" />
        <div class="text-sm">No scans yet</div>
      </div>
    {:else}
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-edge text-left text-xs text-muted">
            <th class="px-5 py-3 font-medium">When</th>
            <th class="px-5 py-3 font-medium">Type</th>
            <th class="px-5 py-3 font-medium">Files</th>
            <th class="px-5 py-3 font-medium">Threats</th>
            <th class="px-5 py-3 font-medium">Duration</th>
            <th class="px-5 py-3 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {#each history as h (h.id)}
            <tr class="border-b border-edge/50 last:border-0">
              <td class="px-5 py-3 text-xs text-muted">{fmtRel(h.started_at)}</td>
              <td class="px-5 py-3 text-xs">{h.kind}</td>
              <td class="px-5 py-3 font-mono text-xs text-muted">
                {h.files_scanned.toLocaleString()}
              </td>
              <td
                class="px-5 py-3 font-mono text-xs {h.threats_found > 0
                  ? 'text-warn'
                  : 'text-muted'}"
              >
                {h.threats_found}
              </td>
              <td class="px-5 py-3 font-mono text-xs text-muted">
                {h.finished_at ? fmtDur(h.finished_at - h.started_at) : "—"}
              </td>
              <td class="px-5 py-3 text-xs {statusColor(h.status)}">{h.status}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</div>
