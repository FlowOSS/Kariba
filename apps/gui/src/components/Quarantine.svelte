<script lang="ts">
  import { Archive, RotateCcw, Trash2, RefreshCw, History } from "@lucide/svelte";
  import * as api from "../lib/api";
  import type { QuarantineItem, ThreatHistoryItem } from "../lib/types";

  let items = $state<QuarantineItem[]>([]);
  let history = $state<ThreatHistoryItem[]>([]);
  let loading = $state(true);
  let message = $state<string | null>(null);

  const VERDICT_STYLE: Record<string, string> = {
    detected: "bg-danger/15 text-danger",
    quarantined: "bg-warn/15 text-warn",
    restored: "bg-accent/15 text-accent",
    deleted: "bg-edge/60 text-muted",
  };

  async function load() {
    loading = true;
    message = null;
    try {
      items = await api.quarantineList();
      history = await api.threatsHistory();
    } catch (e) {
      message = String(e);
      items = [];
      history = [];
    }
    loading = false;
  }
  load();

  async function restore(item: QuarantineItem) {
    try {
      const path = await api.quarantineRestore(item.id);
      message = `Restored to ${path}`;
      await load();
    } catch (e) {
      message = String(e);
    }
  }

  async function remove(item: QuarantineItem) {
    if (!window.confirm(`Permanently delete quarantined file?\n${item.original_path}`)) {
      return;
    }
    try {
      await api.quarantineDelete(item.id);
      message = `Deleted item ${item.id}`;
      await load();
    } catch (e) {
      message = String(e);
    }
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function formatTime(unix: number): string {
    return new Date(unix * 1000).toLocaleString();
  }
</script>

<div class="mx-auto max-w-5xl px-8 py-8">
  <div class="mb-6 flex items-center justify-between">
    <div>
      <h1 class="text-xl font-semibold">Quarantine</h1>
      <p class="text-sm text-muted">
        Isolated files · mode 000 · cannot execute
      </p>
    </div>
    <button class="btn btn-ghost" onclick={load} disabled={loading}>
      <RefreshCw size={14} class={loading ? "animate-spin" : ""} />
      Refresh
    </button>
  </div>

  {#if message}
    <div class="card mb-4 border-accent/30 bg-accent/5 p-3.5 text-sm">{message}</div>
  {/if}

  <div class="card overflow-hidden">
    {#if items.length === 0}
      <div class="flex flex-col items-center gap-3 py-16 text-muted">
        <Archive size={32} class="opacity-40" />
        <div class="text-sm">{loading ? "Loading…" : "Quarantine is empty"}</div>
      </div>
    {:else}
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-edge text-left text-xs text-muted">
            <th class="px-5 py-3 font-medium">ID</th>
            <th class="px-5 py-3 font-medium">Original path</th>
            <th class="px-5 py-3 font-medium">Signature</th>
            <th class="px-5 py-3 font-medium">Size</th>
            <th class="px-5 py-3 font-medium">Quarantined</th>
            <th class="px-5 py-3 text-right font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each items as item (item.id)}
            <tr class="border-b border-edge/50 last:border-0">
              <td class="px-5 py-3 font-mono text-xs text-muted">{item.id}</td>
              <td class="max-w-64 truncate px-5 py-3 font-mono text-xs" title={item.original_path}>
                {item.original_path}
              </td>
              <td class="px-5 py-3 text-xs">{item.signature}</td>
              <td class="px-5 py-3 font-mono text-xs text-muted">{formatSize(item.size)}</td>
              <td class="px-5 py-3 text-xs text-muted">{formatTime(item.quarantined_at)}</td>
              <td class="px-5 py-3">
                <div class="flex justify-end gap-2">
                  <button
                    class="btn btn-ghost px-2.5 py-1.5 text-xs"
                    onclick={() => restore(item)}
                    title="Restore to original location"
                  >
                    <RotateCcw size={13} /> Restore
                  </button>
                  <button
                    class="btn btn-danger px-2.5 py-1.5 text-xs"
                    onclick={() => remove(item)}
                    title="Permanently delete"
                  >
                    <Trash2 size={13} /> Delete
                  </button>
                </div>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>

  <div class="mt-8">
    <div class="mb-3 flex items-center gap-2">
      <History size={15} class="text-muted" />
      <h2 class="text-sm font-semibold">Detection history</h2>
      <span class="text-xs text-muted">every verdict · duplicates kept · resolved items stay</span>
    </div>
    <div class="card overflow-hidden">
      {#if history.length === 0}
        <div class="py-10 text-center text-sm text-muted">
          {loading ? "Loading…" : "No detections recorded yet"}
        </div>
      {:else}
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-edge text-left text-xs text-muted">
              <th class="px-5 py-3 font-medium">When</th>
              <th class="px-5 py-3 font-medium">Path</th>
              <th class="px-5 py-3 font-medium">Signature</th>
              <th class="px-5 py-3 text-right font-medium">Verdict</th>
            </tr>
          </thead>
          <tbody>
            {#each history as h (h.id)}
              <tr class="border-b border-edge/50 last:border-0">
                <td class="whitespace-nowrap px-5 py-3 text-xs text-muted"
                  >{formatTime(h.detected_at)}</td
                >
                <td class="max-w-72 truncate px-5 py-3 font-mono text-xs" title={h.path}>
                  {h.path}
                </td>
                <td class="px-5 py-3 text-xs">{h.signature}</td>
                <td class="px-5 py-3 text-right">
                  <span
                    class="inline-block rounded px-2 py-0.5 font-mono text-[11px] {VERDICT_STYLE[
                      h.status
                    ] ?? VERDICT_STYLE.deleted}"
                  >
                    {h.status}
                  </span>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>
