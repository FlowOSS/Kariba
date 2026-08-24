<script lang="ts">
  import { HeartPulse, RefreshCw } from "@lucide/svelte";
  import * as api from "../lib/api";
  import type { SurveyReport } from "../lib/types";

  let report = $state<SurveyReport | null>(null);
  let loading = $state(true);
  let error = $state<string | null>(null);

  async function run() {
    loading = true;
    error = null;
    try {
      report = await api.survey();
    } catch (e) {
      error = String(e);
      report = null;
    }
    loading = false;
  }
  run();

  function symbol(status: string): string {
    return status === "Ok" ? "●" : status === "Warning" ? "▲" : "✕";
  }
  function color(status: string): string {
    return status === "Ok" ? "text-ok" : status === "Warning" ? "text-warn" : "text-danger";
  }
</script>

<div class="mx-auto max-w-5xl px-8 py-8">
  <div class="mb-6 flex items-center justify-between">
    <div>
      <h1 class="text-xl font-semibold">Survey</h1>
      <p class="text-sm text-muted">
        Detects missing dependencies and shows how to fix them
      </p>
    </div>
    <button class="btn btn-ghost" onclick={run} disabled={loading}>
      <RefreshCw size={14} class={loading ? "animate-spin" : ""} />
      Re-run
    </button>
  </div>

  {#if error}
    <div class="card border-danger/40 bg-danger/5 p-5 text-sm text-danger">{error}</div>
  {:else if report}
    <div class="card mb-6 flex items-center gap-3 p-5">
      <HeartPulse size={18} class="text-accent" />
      <div class="text-sm">
        host: <span class="font-medium">{report.distro.pretty_name}</span>
        <span class="text-muted"> ({report.distro.family} family)</span>
        · init: <span class="font-medium">{report.init}</span>
      </div>
    </div>

    <div class="card p-6">
      {#each report.checks as check (check.engine + check.component)}
        <div class="border-b border-edge/50 py-3 first:pt-0 last:border-0 last:pb-0">
          <div class="flex items-center gap-3 text-sm">
            <span class={color(check.status)}>{symbol(check.status)}</span>
            <span class="w-16 shrink-0 text-xs text-muted">{check.engine}</span>
            <span class="w-44 shrink-0">{check.component}</span>
            <span class="truncate font-mono text-xs text-muted">{check.detail}</span>
          </div>
          {#if check.suggestion}
            <div class="mt-1.5 pl-7 text-xs">
              <span class="font-medium text-accent">↳ fix:</span>
              <code class="ml-1.5 rounded bg-surface-2 px-1.5 py-0.5 font-mono"
                >{check.suggestion}</code
              >
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {:else if loading}
    <div class="card p-10 text-center text-sm text-muted">Running survey…</div>
  {/if}
</div>
