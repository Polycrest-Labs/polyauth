import { ChangeDetectionStrategy, Component, inject, signal, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

interface Item {
  id: string;
  ownerId: string;
  title: string;
  createdAt: string;
}

@Component({
  selector: 'app-items',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="wrap">
      <h1>Your items</h1>
      <form (ngSubmit)="add()">
        <input name="title" [(ngModel)]="title" placeholder="New item title" required />
        <button type="submit" [disabled]="busy()">Add</button>
      </form>
      @if (items().length === 0) {
        <p class="muted">No items yet — add one above.</p>
      } @else {
        <ul>
          @for (item of items(); track item.id) {
            <li>
              <span>{{ item.title }}</span>
              <button type="button" class="link" (click)="remove(item.id)">delete</button>
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .wrap { max-width: 560px; margin: 6vh auto; }
    form { display: flex; gap: 8px; margin-bottom: 18px; }
    input { flex: 1; padding: 9px 10px; border: 1px solid #94a3b8; border-radius: 6px; }
    button { padding: 9px 14px; border: 0; border-radius: 6px; background: #1d4ed8; color: #fff; font-weight: 650; cursor: pointer; }
    ul { list-style: none; padding: 0; }
    li { display: flex; justify-content: space-between; align-items: center; padding: 10px 0; border-bottom: 1px solid #e2e8f0; }
    .link { background: none; color: #b91c1c; padding: 0; }
    .muted { color: #475569; }
  `],
})
export class ItemsComponent implements OnInit {
  private readonly http = inject(HttpClient);

  protected readonly items = signal<Item[]>([]);
  protected readonly busy = signal(false);
  protected title = '';

  async ngOnInit(): Promise<void> {
    await this.refresh();
  }

  protected async add(): Promise<void> {
    if (!this.title.trim() || this.busy()) {
      return;
    }
    this.busy.set(true);
    try {
      await firstValueFrom(this.http.post<Item>('/api/items', { title: this.title.trim() }));
      this.title = '';
      await this.refresh();
    } finally {
      this.busy.set(false);
    }
  }

  protected async remove(id: string): Promise<void> {
    await firstValueFrom(this.http.delete(`/api/items/${id}`));
    await this.refresh();
  }

  private async refresh(): Promise<void> {
    this.items.set(await firstValueFrom(this.http.get<Item[]>('/api/items')));
  }
}
