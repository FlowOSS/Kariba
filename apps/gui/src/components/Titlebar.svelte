<script lang="ts">
  import { Copy, Minus, Square, X } from "@lucide/svelte";
  import { getCurrentWindow } from "@tauri-apps/api/window";

  const win = getCurrentWindow();
  let maximized = $state(false);

  $effect(() => {
    let active = true;
    win.isMaximized().then((m) => active && (maximized = m));
    const unlisten = win.onResized(() => {
      win.isMaximized().then((m) => active && (maximized = m));
    });
    return () => {
      active = false;
      unlisten.then((fn) => fn());
    };
  });

  const btn =
    "inline-flex h-9 w-11 cursor-pointer items-center justify-center text-muted transition-colors hover:bg-surface-2 hover:text-ink";
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<header
  data-tauri-drag-region
  ondblclick={(e) => e.target === e.currentTarget && win.toggleMaximize()}
  class="flex h-9 shrink-0 items-center justify-end border-b border-edge bg-surface"
>
  <button type="button" title="Minimize" class={btn} onclick={() => win.minimize()}>
    <Minus size={14} />
  </button>
  <button
    type="button"
    title={maximized ? "Restore" : "Maximize"}
    class={btn}
    onclick={() => win.toggleMaximize()}
  >
    {#if maximized}
      <Copy size={12} />
    {:else}
      <Square size={12} />
    {/if}
  </button>
  <button
    type="button"
    title="Close"
    class="{btn} hover:bg-danger hover:text-ink"
    onclick={() => win.close()}
  >
    <X size={15} />
  </button>
</header>
