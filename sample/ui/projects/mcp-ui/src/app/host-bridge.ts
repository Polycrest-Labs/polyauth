import { DestroyRef, Injectable, signal } from '@angular/core';

/**
 * Receives tool output from the embedding host. Supports two contexts:
 *  - OpenAI ChatGPT Apps SDK (window.openai + "openai:set_globals" events)
 *  - MCP-Apps hosts (Claude / VS Code) via JSON-RPC postMessage notifications.
 * Falls back to standalone (no host) so the widget can be opened directly for development.
 */
@Injectable({ providedIn: 'root' })
export class HostBridge {
  readonly toolOutput = signal<unknown>(null);
  readonly isHosted = signal(false);

  private readonly messageHandler = (event: MessageEvent) => {
    const data = event.data as { jsonrpc?: string; method?: string; params?: { structuredContent?: unknown } };
    if (event.source !== window.parent || data?.jsonrpc !== '2.0') {
      return;
    }
    if (data.method === 'ui/notifications/tool-result') {
      this.isHosted.set(true);
      this.toolOutput.set(data.params?.structuredContent ?? null);
    }
  };

  private readonly globalsHandler = (event: Event) => {
    const detail = (event as CustomEvent).detail as { globals?: { toolOutput?: unknown } } | undefined;
    this.isHosted.set(true);
    this.toolOutput.set(detail?.globals?.toolOutput ?? null);
  };

  attach(destroyRef: DestroyRef): void {
    // OpenAI ChatGPT Apps SDK: read whatever globals exist now, and listen unconditionally — the host
    // may inject window.openai (and fire openai:set_globals) shortly AFTER the widget bootstraps, so
    // attaching only when window.openai already exists can miss the first tool output.
    this.readOpenAiGlobals();
    window.addEventListener('openai:set_globals', this.globalsHandler, { passive: true });
    destroyRef.onDestroy(() => window.removeEventListener('openai:set_globals', this.globalsHandler));

    // Fallback for hosts that set window.openai.toolOutput without dispatching set_globals: poll briefly
    // (~6s) until tool output arrives, then stop.
    let ticks = 0;
    const timer = setInterval(() => {
      this.readOpenAiGlobals();
      if (this.toolOutput() !== null || ++ticks >= 24) {
        clearInterval(timer);
      }
    }, 250);
    destroyRef.onDestroy(() => clearInterval(timer));

    // MCP-Apps hosts (Claude / VS Code): JSON-RPC tool-result notifications.
    window.addEventListener('message', this.messageHandler);
    destroyRef.onDestroy(() => window.removeEventListener('message', this.messageHandler));

    // Tell an MCP-Apps host we are ready.
    try {
      window.parent?.postMessage({ jsonrpc: '2.0', method: 'ui/notifications/ready' }, '*');
    } catch {
      /* standalone */
    }
  }

  private readOpenAiGlobals(): void {
    const openai = (window as unknown as { openai?: { toolOutput?: unknown } }).openai;
    if (!openai) {
      return;
    }
    this.isHosted.set(true);
    if (openai.toolOutput != null) {
      this.toolOutput.set(openai.toolOutput);
    }
  }
}
