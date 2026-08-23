<script lang="ts">
  import { Play, TriangleAlert } from "@lucide/svelte";
  import * as api from "../lib/api";
  import type { Detection, ScanProgress, ScanResult } from "../lib/types";

  let { preset = [] }: { preset?: string[] } = $props();

  let paths = $state("~/Downloads");
  let quarantine = $state(true);
  let running = $state(false);
  let progress = $state<ScanProgress | null>(null);
  let detections = $state<Detection[]>([]);
  let result = $state<ScanResult | null>(null);
  let error = $state<string | null>(null);

  $effect(() => {
    if (preset.length > 0) {
      paths = preset.join("\n");
    }
  });

  async function start() {
    const pathList = paths
      .split(/[\n,]+/)
      .map((p) => p.trim())
      .filter(Boolean);
    if (pathList.length === 0 || running) return;

    running = true;
    result = null;
    error = null;
    detections = [];
    progress = null;

    const unProgress = await api.onScanProgress((p) => (progress = p));
    const unDetection = await api.onScanDetection((d) => (detections = [...detections, d]));

    try {
      result = await api.scan(pathList, quarantine);
    } catch (e) {
      error = String(e);
    } finally {
      unProgress();
      unDetection();
      running = false;
    }
  }
</script>

<div class="mx-auto max-w-5xl px-8 py-8">
  <div class="mb-6">
    <h1 class="text-xl font-semibold">Scan</h1>
    <p class="text-sm text-muted">On-demand scanning via karibad → ClamAV</p>
  </div>

  <div class="card mb-6 p-6">
    <div class="label mb-2">Paths (one per line)</div>
    <textarea
      class="h-24 w-full resize-none rounded-lg border border-edge bg-bg p-3 font-mono text-sm outline-none focus:border-accent"
      bind:value={paths}
      disabled={running}
      spellcheck="false"
    ></textarea>

    <div class="mt-4 flex items-center justify-between">
      <label class="flex cursor-pointer items-center gap-2.5 text-sm text-muted">
        <input type="checkbox" bind:checked={quarantine} disabled={running} class="accent-(--color-accent)" />
        Quarantine threats automatically
      </label>
      <button class="btn btn-primary" onclick={start} disabled={running}>
        <Play size={15} />
        {running ? "Scanning…" : "Start Scan"}
      </button>
    </div>
  </div>

  {#if running || progress}
    <div class="card mb-6 p-6">
      <div class="mb-3 h-1.5 overflow-hidden rounded-full bg-surface-2">
        <div
          class="h-full w-1/3 rounded-full bg-accent"
          style="animation: slide 1.2s ease-in-out infinite"
        ></div>
      </div>
      {#if progress}
        <div class="flex items-center justify-between text-sm">
          <span class="font-mono text-xs text-muted">{progress.current}</span>
          <span class="shrink-0 pl-4 font-mono text-xs">
            {progress.files_scanned.toLocaleString()} files · {progress.threats_found}
            threat(s)
          </span>
        </div>
      {/if}
    </div>
  {/if}

  {#if error}
    <div class="card mb-6 border-danger/40 bg-danger/5 p-5 text-sm text-danger">
      {error}
    </div>
  {/if}

  {#if result}
    <div
      class="card mb-6 p-5 {result.threats_found > 0
        ? 'border-warn/40 bg-warn/5'
        : 'border-ok/30 bg-ok/5'}"
    >
      <div class="text-sm">
        Scanned <span class="font-mono">{result.files_scanned.toLocaleString()}</span>
        files in <span class="font-mono">{result.duration_ms}ms</span> ·
        <span class={result.threats_found > 0 ? "font-semibold text-warn" : "text-ok"}>
          {result.threats_found} threat(s) found
        </span>
        {#if quarantine && result.quarantined > 0}
          · <span class="font-semibold">{result.quarantined} quarantined</span>
        {/if}
      </div>
    </div>
  {/if}

  {#if detections.length > 0}
    <div class="card p-6">
      <div class="label mb-4">Detected ({detections.length})</div>
      <div class="space-y-2">
        {#each detections as detection (detection.path + detection.signature)}
          <div class="flex items-center gap-3 text-sm">
            <TriangleAlert size={15} class="shrink-0 text-warn" />
            <span class="truncate font-mono text-xs">{detection.path}</span>
            <span class="ml-auto shrink-0 text-xs text-muted">
              {detection.engine} · {detection.signature}
            </span>
          </div>
        {/each}
      </div>
    </div>
  {/if}
</div>
