<script lang="ts">
  import { Waves, Zap, ShieldCheck, ShieldOff, ExternalLink } from "@lucide/svelte";
  import * as api from "../lib/api";
  import { fmtRel } from "../lib/format";
  import type { ScanHistoryItem, StatusResult, ThreatHistoryItem } from "../lib/types";

  let status = $state<StatusResult | null>(null);
  let daemonUp = $state(true);
  let lastScan = $state<ScanHistoryItem | null>(null);
  let catches = $state<ThreatHistoryItem[]>([]);
  let scanning = $state(false);

  const VERDICT_STYLE: Record<string, string> = {
    detected: "bg-danger/15 text-danger",
    quarantined: "bg-warn/15 text-warn",
    restored: "bg-accent/15 text-accent",
    deleted: "bg-edge/60 text-muted",
  };

  async function refresh() {
    try {
      status = await api.daemonStatus();
      daemonUp = true;
    } catch {
      daemonUp = false;
      status = null;
    }
    try {
      const history = await api.scanHistory();
      lastScan = history[0] ?? null;
      catches = (await api.threatsHistory()).slice(0, 4);
    } catch {
      /* daemon down: keep last values */
    }
  }
  refresh();

  $effect(() => {
    const id = setInterval(refresh, 5000);
    let unlisten: (() => void) | undefined;
    api.onRealtimeDetection(() => refresh()).then((u) => (unlisten = u));
    return () => {
      clearInterval(id);
      unlisten?.();
    };
  });

  async function runScan(paths: string[], kind: string) {
    if (scanning) return;
    scanning = true;
    try {
      const settings = await api.settingsGet();
      await api.scan(paths, settings.scan.default_quarantine, kind);
    } catch {
      /* surfaced via status on next refresh */
    }
    scanning = false;
    refresh();
  }

  const quickScan = () => runScan(["~/Downloads", "/tmp", "/var/tmp"], "quick");
  const fullScan = () => runScan(["/"], "full");

  async function toggleRealtime() {
    try {
      const settings = await api.settingsGet();
      settings.realtime.enabled = !settings.realtime.enabled;
      await api.settingsSet(settings);
      refresh();
    } catch {
      /* daemon down */
    }
  }

  let pill = $derived.by(() => {
    if (!daemonUp) return { text: "offline", cls: "bg-edge/60 text-muted" };
    if (!status?.protection_enabled)
      return { text: "protection off", cls: "bg-warn/15 text-warn" };
    return { text: "protected", cls: "bg-ok/15 text-ok" };
  });
</script>

<div class="flex h-full flex-col bg-bg text-ink">
  <div class="flex items-center justify-between px-4 pb-3 pt-4">
    <div class="flex items-center gap-2">
      <span class="flex h-6 w-6 items-center justify-center rounded-md bg-accent/15 text-accent">
        <Waves size={13} />
      </span>
      <span class="text-xs font-semibold tracking-widest">KARIBA</span>
    </div>
    <span class="rounded-full px-2.5 py-1 text-[11px] font-medium {pill.cls}">{pill.text}</span>
  </div>

  <div class="mx-4 space-y-1.5 rounded-lg border border-edge bg-surface p-3 text-xs">
    {#if !daemonUp}
      <div class="flex items-center gap-2 text-muted">
        <ShieldOff size={13} /> karibad is not running
      </div>
    {:else}
      <div class="flex items-center justify-between">
        <span class="text-muted">Real-time</span>
        <button
          class="cursor-pointer font-mono {status?.realtime_active
            ? 'text-ok'
            : 'text-muted'} hover:underline"
          onclick={toggleRealtime}
          title="Toggle real-time protection"
        >
          {status?.realtime_active ? "watching ▸ on" : "inactive ▸ off"}
        </button>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted">Last scan</span>
        <span class="font-mono">
          {#if lastScan}
            {lastScan.kind} · {fmtRel(lastScan.started_at)} · {lastScan.threats_found} threat(s)
          {:else}
            never
          {/if}
        </span>
      </div>
      <div class="flex items-center justify-between">
        <span class="text-muted">Quarantine</span>
        <span class="font-mono">{status?.quarantined_items ?? 0} item(s)</span>
      </div>
    {/if}
  </div>

  <div class="mx-4 mt-3 flex items-center gap-2">
    <span class="label">Recent catches</span>
  </div>
  <div class="mx-4 mt-1.5 flex-1 overflow-y-auto rounded-lg border border-edge bg-surface">
    {#if catches.length === 0}
      <div class="flex h-full min-h-16 items-center justify-center gap-2 text-xs text-muted">
        <ShieldCheck size={13} /> nothing caught yet
      </div>
    {:else}
      <div class="divide-y divide-edge/50">
        {#each catches as c (c.id)}
          <div class="px-3 py-2">
            <div class="truncate font-mono text-[11px]" title={c.path}>{c.path}</div>
            <div class="mt-1 flex items-center justify-between gap-2">
              <span class="truncate text-[11px] text-muted">
                {c.signature} · {fmtRel(c.detected_at)}
              </span>
              <span
                class="shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] {VERDICT_STYLE[
                  c.status
                ] ?? VERDICT_STYLE.deleted}"
              >
                {c.status}
              </span>
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>

  <div class="flex gap-2 px-4 pb-2 pt-3">
    <button class="btn flex-1" onclick={quickScan} disabled={scanning || !daemonUp}>
      <Zap size={13} />
      {scanning ? "Scanning…" : "Quick"}
    </button>
    <button class="btn flex-1" onclick={fullScan} disabled={scanning || !daemonUp}>
      Full
    </button>
  </div>
  <div class="flex gap-2 px-4 pb-4">
    <button class="btn btn-ghost flex-1" onclick={() => api.showMainWindow()}>
      <ExternalLink size={13} /> Open Kariba
    </button>
  </div>
</div>
