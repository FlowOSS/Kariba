<script lang="ts">
  import Titlebar from "./components/Titlebar.svelte";
  import Sidebar from "./components/Sidebar.svelte";
  import Dashboard from "./components/Dashboard.svelte";
  import ScanView from "./components/Scan.svelte";
  import Quarantine from "./components/Quarantine.svelte";
  import Survey from "./components/Survey.svelte";
  import type { View } from "./lib/types";

  let view = $state<View>("dashboard");
  let scanPreset = $state<string[]>([]);

  function quickScan(paths: string[]) {
    scanPreset = paths;
    view = "scan";
  }
</script>

<div class="flex h-full flex-col">
  <Titlebar />
  <div class="flex min-h-0 flex-1">
    <Sidebar {view} onnavigate={(v) => (view = v)} />
    <main class="flex-1 overflow-y-auto">
      {#if view === "dashboard"}
        <Dashboard onquickscan={quickScan} />
      {:else if view === "scan"}
        <ScanView preset={scanPreset} />
      {:else if view === "quarantine"}
        <Quarantine />
      {:else}
        <Survey />
      {/if}
    </main>
  </div>
</div>
