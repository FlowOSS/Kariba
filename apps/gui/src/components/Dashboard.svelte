<script lang="ts">
  import {
    ShieldCheck,
    ShieldAlert,
    ShieldOff,
    RefreshCw,
    Zap,
    Globe,
    FolderSearch,
    Terminal,
  } from "@lucide/svelte";
  import * as api from "../lib/api";
  import { fmtRel } from "../lib/format";
  import type {
    RealtimeDetection,
    ScanHistoryItem,
    StatusResult,
    SurveyReport,
    View,
  } from "../lib/types";

  let {
    onquickscan,
    onnavigate,
  }: { onquickscan: (paths: string[]) => void; onnavigate: (v: View) => void } = $props();

  let status = $state<StatusResult | null>(null);
  let report = $state<SurveyReport | null>(null);
  let lastScan = $state<ScanHistoryItem | null>(null);
  let daemonUp = $state(true);
  let loading = $state(true);
  let rtDetections = $state<RealtimeDetection[]>([]);

  $effect(() => {
    let unlisten: (() => void) | undefined;
    api.onRealtimeDetection((d) => {
      rtDetections = [d, ...rtDetections].slice(0, 5);
    }).then((u) => (unlisten = u));
    return () => unlisten?.();
  });

  async function load() {
    loading = true;
    try {
      status = await api.daemonStatus();
      daemonUp = true;
    } catch {
      daemonUp = false;
      status = null;
    }
    try {
      report = await api.survey();
    } catch {
      report = null;
    }
    try {
      const h = await api.scanHistory();
      lastScan = h[0] ?? null;
    } catch {
      lastScan = null;
    }
    loading = false;
  }
  load();

  let enginesOk = $derived(
    report ? report.checks.every((c) => c.status === "Ok") : false,
  );
  let protected_ = $derived(daemonUp && enginesOk);
</script>

<div class="mx-auto max-w-5xl px-8 py-8">
  <div class="mb-6 flex items-center justify-between">
    <div>
      <h1 class="text-xl font-semibold">Dashboard</h1>
      <p class="text-sm text-muted">System security at a glance</p>
    </div>
    <button class="btn btn-ghost" onclick={load} disabled={loading}>
      <RefreshCw size={14} class={loading ? "animate-spin" : ""} />
      Refresh
    </button>
  </div>

  {#if !daemonUp}
    <div class="card mb-6 flex items-start gap-3 border-danger/40 bg-danger/5 p-5">
      <ShieldOff size={20} class="mt-0.5 shrink-0 text-danger" />
      <div>
        <div class="font-medium text-danger">karibad is not running</div>
        <div class="mt-1 text-sm text-muted">
          Start the daemon in a terminal:
          <code class="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-ink"
            >karibad</code
          >
          (or <code class="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-ink"
            >cargo run -p karibad</code
          > during development).
        </div>
      </div>
    </div>
  {/if}

  <div class="mb-6 grid grid-cols-3 gap-4">
    <div class="card col-span-1 p-6">
      <div class="label mb-4">System status</div>
  {#if rtDetections.length > 0}
    <div class="card mb-6 border-danger/40 bg-danger/5 p-5">
      <div class="mb-3 flex items-center gap-2.5 font-medium text-danger">
        <ShieldAlert size={18} /> Real-time detection{rtDetections.length > 1 ? "s" : ""}
      </div>
      <div class="space-y-2">
        {#each rtDetections as d (d.path + d.signature + d.action)}
          <div class="text-xs">
            <span class="font-mono text-ink">{d.path}</span>
            <span class="text-muted"> · {d.signature} · {d.action}</span>
          </div>
        {/each}
      </div>
    </div>
  {/if}

  {#if !daemonUp}
        <div class="flex items-center gap-3 text-danger">
          <ShieldOff size={34} />
          <div>
            <div class="text-lg font-semibold">Offline</div>
            <div class="text-xs text-muted">daemon unreachable</div>
          </div>
        </div>
      {:else if status && !status.protection_enabled}
        <div class="flex items-center gap-3 text-warn">
          <ShieldOff size={34} />
          <div>
            <div class="text-lg font-semibold">Protection off</div>
            <button
              class="cursor-pointer text-xs text-accent hover:underline"
              onclick={() => onnavigate("settings")}
            >
              Settings ▸ to re-enable
            </button>
          </div>
        </div>
      {:else if protected_}
        <div class="flex items-center gap-3 text-ok">
          <ShieldCheck size={34} />
          <div>
            <div class="text-lg font-semibold">Protected</div>
            <div class="text-xs text-muted">all engines operational</div>
          </div>
        </div>
      {:else}
        <div class="flex items-center gap-3 text-warn">
          <ShieldAlert size={34} />
          <div>
            <div class="text-lg font-semibold">Attention</div>
            <div class="text-xs text-muted">see Survey for fixes</div>
          </div>
        </div>
      {/if}
      {#if status}
        <div class="mt-5 space-y-1 border-t border-edge pt-4 text-xs text-muted">
          <div class="flex justify-between">
            <span>Scans</span><span class="font-mono text-ink">{status.scans_total}</span>
          </div>
          <div class="flex justify-between">
            <span>Threats found</span
            ><span class="font-mono text-ink">{status.threats_total}</span>
          </div>
          <div class="flex justify-between">
            <span>Quarantined</span
            ><span class="font-mono text-ink">{status.quarantined_items}</span>
          </div>
          <div class="flex justify-between gap-4">
            <span class="shrink-0">Real-time</span>
            <span
              class="truncate text-right font-mono {status.realtime_active
                ? 'text-ok'
                : 'text-muted'}"
              title={status.realtime_detail}
            >
              {status.realtime_active ? "watching" : "inactive"}
            </span>
          </div>
          {#if lastScan}
            <div class="flex justify-between">
              <span>Last scan</span
              ><span class="font-mono text-ink"
                >{lastScan.kind} · {fmtRel(lastScan.started_at)} · {lastScan.threats_found}
                threat(s)</span
              >
            </div>
          {/if}
        </div>
      {/if}
    </div>

    <div class="card col-span-2 p-6">
      <div class="label mb-4">Quick actions</div>
      <div class="grid grid-cols-2 gap-3">
        <button
          class="btn btn-primary justify-center py-3"
          onclick={() => onquickscan(["~/Downloads", "/tmp", "/var/tmp"])}
        >
          <Zap size={15} /> Quick Scan
        </button>
        <button
          class="btn btn-ghost justify-center py-3"
          onclick={() => onquickscan(["/"])}
        >
          <Globe size={15} /> Full Scan
        </button>
        <button
          class="btn btn-ghost justify-center py-3"
          onclick={() => onquickscan(["~/Downloads"])}
        >
          <FolderSearch size={15} /> Downloads
        </button>
        <button class="btn btn-ghost justify-center py-3" disabled title="post-MVP">
          <Terminal size={15} /> Update DBs
        </button>
      </div>
    </div>
  </div>

  <div class="card p-6">
    <div class="label mb-4">Engine status</div>
    {#if report}
      <div class="mb-4 text-xs text-muted">
        host: {report.distro.pretty_name} · init: {report.init}
      </div>
      <div class="space-y-2">
        {#each report.checks as check (check.component)}
          <div class="flex items-center gap-3 text-sm">
            <span
              class={check.status === "Ok"
                ? "text-ok"
                : check.status === "Warning"
                  ? "text-warn"
                  : "text-danger"}
            >
              {check.status === "Ok" ? "●" : check.status === "Warning" ? "▲" : "✕"}
            </span>
            <span class="w-44 shrink-0 text-muted">{check.component}</span>
            <span class="truncate font-mono text-xs text-ink/80">{check.detail}</span>
          </div>
        {/each}
      </div>
    {:else}
      <div class="text-sm text-muted">Survey unavailable — is karibad running?</div>
    {/if}
  </div>
</div>
