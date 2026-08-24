<script lang="ts">
  import { TriangleAlert, RotateCcw, Plus, X } from "@lucide/svelte";
  import * as api from "../lib/api";
  import { BUILTIN_EXCLUSION_PATHS } from "../lib/types";
  import type { Settings } from "../lib/types";

  let settings = $state<Settings | null>(null);
  let daemonUp = $state(true);
  let error = $state<string | null>(null);
  let saving = $state(false);

  let newPath = $state("");
  let newExt = $state("");

  let confirmDisable = $state(false);
  let removeTarget = $state<string | null>(null);

  let missingBuiltins = $derived.by(() => {
    const s = settings;
    if (!s) return [];
    return BUILTIN_EXCLUSION_PATHS.filter((b) => !s.exclusions.paths.includes(b));
  });

  const BUILTIN_REASONS: Record<string, string> = {
    "/proc": "Kernel process pseudo-files. Scanning them is pointless and can stall the engine.",
    "/sys": "Kernel device pseudo-files. Scanning them is pointless and can stall the engine.",
    "/dev": "Device nodes. Reading them can hang scans or have side effects.",
    "/run": "Runtime sockets and ephemeral state. Constantly changing, nothing to scan.",
  };

  async function load() {
    try {
      settings = await api.settingsGet();
      daemonUp = true;
      error = null;
    } catch (e) {
      daemonUp = false;
      settings = null;
      error = String(e);
    }
  }
  load();

  async function save(next: Settings) {
    saving = true;
    error = null;
    try {
      settings = await api.settingsSet(next);
    } catch (e) {
      error = String(e);
    }
    saving = false;
  }

  function toggleRealtime() {
    if (!settings) return;
    if (settings.realtime.enabled) {
      confirmDisable = true;
    } else {
      save({ ...settings, realtime: { ...settings.realtime, enabled: true } });
    }
  }

  function confirmDisableNow() {
    if (!settings) return;
    confirmDisable = false;
    save({ ...settings, realtime: { ...settings.realtime, enabled: false } });
  }

  function toggleAutoQuarantine() {
    if (!settings) return;
    save({
      ...settings,
      realtime: { ...settings.realtime, auto_quarantine: !settings.realtime.auto_quarantine },
    });
  }

  function toggleDefaultQuarantine() {
    if (!settings) return;
    save({
      ...settings,
      scan: { ...settings.scan, default_quarantine: !settings.scan.default_quarantine },
    });
  }

  function requestRemovePath(path: string) {
    if (BUILTIN_EXCLUSION_PATHS.includes(path)) {
      removeTarget = path;
    } else {
      removePath(path);
    }
  }

  function removePath(path: string) {
    if (!settings) return;
    removeTarget = null;
    save({
      ...settings,
      exclusions: {
        ...settings.exclusions,
        paths: settings.exclusions.paths.filter((p) => p !== path),
      },
    });
  }

  function addPath() {
    if (!settings) return;
    const path = newPath.trim();
    if (!path || settings.exclusions.paths.includes(path)) {
      newPath = "";
      return;
    }
    newPath = "";
    save({
      ...settings,
      exclusions: { ...settings.exclusions, paths: [...settings.exclusions.paths, path] },
    });
  }

  function removeExt(ext: string) {
    if (!settings) return;
    save({
      ...settings,
      exclusions: {
        ...settings.exclusions,
        extensions: settings.exclusions.extensions.filter((e) => e !== ext),
      },
    });
  }

  function addExt() {
    if (!settings) return;
    let ext = newExt.trim();
    if (!ext) return;
    ext = ext.replace(/^\*?\.?/, "*.").toLowerCase();
    newExt = "";
    if (settings.exclusions.extensions.includes(ext)) return;
    save({
      ...settings,
      exclusions: { ...settings.exclusions, extensions: [...settings.exclusions.extensions, ext] },
    });
  }

  function restoreBuiltins() {
    if (!settings) return;
    const paths = [...settings.exclusions.paths, ...missingBuiltins];
    save({ ...settings, exclusions: { ...settings.exclusions, paths } });
  }
</script>

{#snippet toggle(value: boolean, onchange: () => void, label: string)}
  <button
    type="button"
    role="switch"
    aria-checked={value}
    aria-label={label}
    onclick={onchange}
    disabled={saving}
    class="relative h-6 w-11 shrink-0 cursor-pointer rounded-full transition-colors disabled:opacity-40 {value
      ? 'bg-accent'
      : 'border border-edge bg-surface-2'}"
  >
    <span
      class="absolute top-1/2 h-4 w-4 -translate-y-1/2 rounded-full transition-all {value
        ? 'left-6 bg-bg'
        : 'left-1 bg-muted'}"
    ></span>
  </button>
{/snippet}

<div class="mx-auto max-w-3xl px-8 py-8">
  <div class="mb-6 flex items-center justify-between">
    <div>
      <h1 class="text-xl font-semibold">Settings</h1>
      <p class="text-sm text-muted">Protection, scanning, and exclusions</p>
    </div>
    {#if saving}
      <span class="text-xs text-muted">saving…</span>
    {/if}
  </div>

  {#if !daemonUp}
    <div class="card mb-6 border-danger/40 bg-danger/5 p-5 text-sm text-danger">
      karibad is not running. Start it to view or change settings.
    </div>
  {/if}

  {#if error}
    <div class="card mb-6 border-danger/40 bg-danger/5 p-4 font-mono text-xs text-danger">
      {error}
    </div>
  {/if}

  {#if settings}
    <div class="card mb-6 p-6">
      <div class="label mb-5">Protection</div>

      <div class="flex items-start justify-between gap-6">
        <div>
          <div class="text-sm font-medium">Real-time protection</div>
          <div class="mt-1 text-xs text-muted">
            Watch files as they land and gate execution of threats. Takes effect once real-time
            scanning is active.
          </div>
        </div>
        {@render toggle(settings.realtime.enabled, toggleRealtime, "Real-time protection")}
      </div>

      <div class="mt-5 flex items-start justify-between gap-6 border-t border-edge pt-5">
        <div>
          <div class="text-sm font-medium">Auto-quarantine detections</div>
          <div class="mt-1 text-xs text-muted">
            Move threats to quarantine automatically on detection.
          </div>
        </div>
        {@render toggle(settings.realtime.auto_quarantine, toggleAutoQuarantine, "Auto-quarantine detections")}
      </div>
    </div>

    <div class="card mb-6 p-6">
      <div class="label mb-5">Scanning</div>
      <div class="flex items-start justify-between gap-6">
        <div>
          <div class="text-sm font-medium">Quarantine threats by default</div>
          <div class="mt-1 text-xs text-muted">
            Applies to scans started without an explicit choice.
          </div>
        </div>
        {@render toggle(settings.scan.default_quarantine, toggleDefaultQuarantine, "Quarantine threats by default")}
      </div>
    </div>

    <div class="card p-6">
      <div class="label mb-5">Exclusions</div>

      <div class="mb-2 flex items-center justify-between">
        <div class="text-sm font-medium">Paths never scanned</div>
      </div>
      <div class="divide-y divide-edge rounded-lg border border-edge">
        {#each settings.exclusions.paths as path (path)}
          <div class="flex items-center gap-3 px-4 py-2.5 text-sm">
            <span class="flex-1 truncate font-mono text-xs">{path}</span>
            {#if BUILTIN_EXCLUSION_PATHS.includes(path)}
              <span class="rounded bg-surface-2 px-1.5 py-0.5 text-[10px] tracking-wider text-muted uppercase"
                >built-in</span
              >
            {/if}
            <button
              class="cursor-pointer text-muted transition-colors hover:text-danger"
              onclick={() => requestRemovePath(path)}
              title="Remove exclusion"
            >
              <X size={14} />
            </button>
          </div>
        {/each}
      </div>
      <div class="mt-3 flex gap-2">
        <input
          class="flex-1 rounded-lg border border-edge bg-bg px-3 py-2 font-mono text-xs outline-none focus:border-accent"
          placeholder="/path/to/exclude or ~/folder"
          bind:value={newPath}
          onkeydown={(e) => e.key === "Enter" && addPath()}
          spellcheck="false"
        />
        <button class="btn btn-ghost" onclick={addPath} disabled={!newPath.trim()}>
          <Plus size={14} /> Add path
        </button>
      </div>

      {#if missingBuiltins.length > 0}
        <div class="mt-4 flex items-start gap-3 rounded-lg border border-warn/40 bg-warn/5 p-4">
          <TriangleAlert size={16} class="mt-0.5 shrink-0 text-warn" />
          <div class="flex-1 text-xs">
            <div class="font-medium text-warn">
              {missingBuiltins.length} built-in exclusion{missingBuiltins.length > 1 ? "s" : ""}
              removed ({missingBuiltins.join(", ")})
            </div>
            <div class="mt-1 text-muted">
              Scans may hang on kernel pseudo-files or device nodes.
            </div>
          </div>
          <button class="btn btn-ghost shrink-0" onclick={restoreBuiltins}>
            <RotateCcw size={13} /> Restore built-ins
          </button>
        </div>
      {/if}

      <div class="mt-6 mb-2 text-sm font-medium">File types skipped</div>
      {#if settings.exclusions.extensions.length > 0}
        <div class="mb-3 flex flex-wrap gap-2">
          {#each settings.exclusions.extensions as ext (ext)}
            <span
              class="inline-flex items-center gap-1.5 rounded-lg border border-edge bg-surface-2 px-2.5 py-1 font-mono text-xs"
            >
              {ext}
              <button
                class="cursor-pointer text-muted transition-colors hover:text-danger"
                onclick={() => removeExt(ext)}
              >
                <X size={12} />
              </button>
            </span>
          {/each}
        </div>
      {:else}
        <div class="mb-3 text-xs text-muted">No file types excluded.</div>
      {/if}
      <div class="flex gap-2">
        <input
          class="w-48 rounded-lg border border-edge bg-bg px-3 py-2 font-mono text-xs outline-none focus:border-accent"
          placeholder="*.iso"
          bind:value={newExt}
          onkeydown={(e) => e.key === "Enter" && addExt()}
          spellcheck="false"
        />
        <button class="btn btn-ghost" onclick={addExt} disabled={!newExt.trim()}>
          <Plus size={14} /> Add pattern
        </button>
      </div>
    </div>
  {/if}
</div>

{#if confirmDisable && settings}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
    <div class="card w-[26rem] p-6">
      <div class="flex items-center gap-2.5 font-medium text-warn">
        <TriangleAlert size={18} /> Turn off protection?
      </div>
      <p class="mt-3 text-sm text-muted">
        Kariba will stop watching new files and will no longer gate execution of threats. Your
        system stays unprotected until you turn it back on.
      </p>
      <div class="mt-5 flex justify-end gap-2">
        <button class="btn btn-ghost" onclick={() => (confirmDisable = false)}>Cancel</button>
        <button class="btn btn-danger" onclick={confirmDisableNow}>Turn off</button>
      </div>
    </div>
  </div>
{/if}

{#if removeTarget && settings}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
    <div class="card w-[28rem] p-6">
      <div class="flex items-center gap-2.5 font-medium text-warn">
        <TriangleAlert size={18} /> Remove built-in exclusion “{removeTarget}”?
      </div>
      <p class="mt-3 text-sm text-muted">
        {BUILTIN_REASONS[removeTarget] ?? "Built-in exclusions exist for good reasons."}
      </p>
      <p class="mt-2 text-sm text-muted">
        Removing this may hang scans or cause spurious errors. Only do this if you know why.
      </p>
      <div class="mt-5 flex justify-end gap-2">
        <button class="btn btn-ghost" onclick={() => (removeTarget = null)}>Keep it</button>
        <button
          class="btn btn-danger"
          onclick={() => {
            const target = removeTarget;
            if (target) removePath(target);
          }}
        >
          Remove anyway
        </button>
      </div>
    </div>
  </div>
{/if}
