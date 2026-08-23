<script lang="ts">
  import { LayoutDashboard, ScanSearch, Archive, HeartPulse, Waves } from "@lucide/svelte";
  import type { View } from "../lib/types";
  import { daemonStatus } from "../lib/api";

  let { view, onnavigate }: { view: View; onnavigate: (v: View) => void } = $props();

  let daemonUp = $state<boolean | null>(null);

  $effect(() => {
    let active = true;
    async function poll() {
      while (active) {
        try {
          await daemonStatus();
          daemonUp = true;
        } catch {
          daemonUp = false;
        }
        await new Promise((r) => setTimeout(r, 5000));
      }
    }
    poll();
    return () => {
      active = false;
    };
  });

  const items = [
    { id: "dashboard" as View, label: "Dashboard", icon: LayoutDashboard },
    { id: "scan" as View, label: "Scan", icon: ScanSearch },
    { id: "quarantine" as View, label: "Quarantine", icon: Archive },
    { id: "survey" as View, label: "Survey", icon: HeartPulse },
  ];
</script>

<aside class="flex w-56 shrink-0 flex-col border-r border-edge bg-surface">
  <div class="flex items-center gap-2.5 px-5 py-5">
    <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/15 text-accent">
      <Waves size={18} />
    </div>
    <div>
      <div class="text-sm font-semibold tracking-widest">KARIBA</div>
      <div class="text-[10px] text-muted">hold back the flood</div>
    </div>
  </div>

  <nav class="mt-2 flex flex-col gap-1 px-3">
    {#each items as { id, label, icon: Icon } (id)}
      <button
        class="flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors {view === id
          ? 'bg-surface-2 text-ink'
          : 'text-muted hover:bg-surface-2/60 hover:text-ink'}"
        onclick={() => onnavigate(id)}
      >
        <Icon size={16} />
        {label}
      </button>
    {/each}
  </nav>

  <div class="mt-auto px-5 py-4 text-xs text-muted">
    <div class="flex items-center gap-2">
      <span
        class="h-2 w-2 rounded-full {daemonUp === null
          ? 'bg-muted'
          : daemonUp
            ? 'bg-ok'
            : 'bg-danger'}"
      ></span>
      {#if daemonUp === null}
        connecting…
      {:else if daemonUp}
        karibad connected
      {:else}
        karibad offline
      {/if}
    </div>
  </div>
</aside>
