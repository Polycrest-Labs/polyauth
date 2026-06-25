import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject } from '@angular/core';
import { HostBridge } from './host-bridge';

interface Item {
  id: string;
  title: string;
  createdAt: string;
}

@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="widget">
      <h2>Items</h2>
      @if (items().length === 0) {
        <p class="muted">No items to display{{ bridge.isHosted() ? '' : ' (open from an MCP host to see data)' }}.</p>
      } @else {
        <ul>
          @for (item of items(); track item.id) {
            <li>{{ item.title }}</li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .widget { font-family: system-ui, sans-serif; padding: 12px; }
    h2 { margin: 0 0 8px; font-size: 1.1rem; }
    ul { list-style: none; padding: 0; margin: 0; }
    li { padding: 6px 0; border-bottom: 1px solid #e2e8f0; }
    .muted { color: #475569; }
  `],
})
export class App {
  protected readonly bridge = inject(HostBridge);

  protected readonly items = computed<Item[]>(() => {
    const output = this.bridge.toolOutput() as { items?: Item[] } | Item[] | null;
    if (Array.isArray(output)) {
      return output;
    }
    return output?.items ?? [];
  });

  constructor() {
    this.bridge.attach(inject(DestroyRef));
  }
}
