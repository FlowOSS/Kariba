<script lang="ts">
  import Titlebar from "./components/Titlebar.svelte";
  import Sidebar from "./components/Sidebar.svelte";
  import Dashboard from "./components/Dashboard.svelte";
  import ScanView from "./components/Scan.svelte";
  import Quarantine from "./components/Quarantine.svelte";
  import Survey from "./components/Survey.svelte";
  import SettingsView from "./components/Settings.svelte";
  import type { View } from "./lib/types";
  import { startRealtimeEvents, onRealtimeDetection } from "./lib/api";

  let view = $state<View>("dashboard");
  let scanPreset = $state<string[]>([]);
  let unseenCatches = $state(0);

  $effect(() => {
    startRealtimeEvents().catch(() => {});
  });

  $effect(() => {
    let unlisten: (() => void) | undefined;
    onRealtimeDetection(() => {
      unseenCatches += 1;
    }).then((u) => (unlisten = u));
    return () => unlisten?.();
  });

  function quickScan(paths: string[]) {
    scanPreset = paths;
    view = "scan";
  }

  function navigate(v: View) {
    view = v;
    if (v === "quarantine") {
      unseenCatches = 0;
    }
  }
</script>

<div class="flex h-full flex-col">
  <Titlebar />
  <div class="flex min-h-0 flex-1">
    <Sidebar {view} onnavigate={navigate} unseen={unseenCatches} />
    <main class="flex-1 overflow-y-auto">
      {#if view === "dashboard"}
        <Dashboard onquickscan={quickScan} onnavigate={navigate} />
      {:else if view === "scan"}
        <ScanView preset={scanPreset} onnavigate={navigate} />
      {:else if view === "quarantine"}
        <Quarantine />
      {:else if view === "survey"}
        <Survey />
      {:else}
        <SettingsView />
      {/if}
    </main>
  </div>
</div>
