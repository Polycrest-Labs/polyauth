import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../auth/auth.service';

@Component({
  selector: 'app-login',
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <section class="card">
      <h1>Sign in</h1>
      @if (auth.configError(); as cfg) {
        <p class="error" role="alert">{{ cfg }}</p>
        <p class="muted">The app is deployed but Firebase isn't wired up yet — set the Firebase web config in <code>/config.json</code>.</p>
      } @else {
        <form (ngSubmit)="submit()">
          <label for="email">Email</label>
          <input id="email" name="email" type="email" autocomplete="username" [(ngModel)]="email" required />

          <label for="password">Password</label>
          <input id="password" name="password" type="password" autocomplete="current-password" [(ngModel)]="password" required />

          <button type="submit" [disabled]="busy()">{{ busy() ? 'Signing in…' : 'Sign in' }}</button>
        </form>
        @if (auth.error(); as err) {
          <p class="error" role="alert">{{ err }}</p>
        }
      }
    </section>
  `,
  styles: [`
    .card { max-width: 360px; margin: 8vh auto; padding: 28px; border: 1px solid #cbd5e1; border-radius: 10px; background: #fff; }
    h1 { margin-top: 0; }
    label { display: block; margin: 12px 0 4px; font-weight: 600; color: #334155; }
    input { width: 100%; padding: 9px 10px; border: 1px solid #94a3b8; border-radius: 6px; box-sizing: border-box; }
    button { margin-top: 18px; width: 100%; padding: 10px; border: 0; border-radius: 6px; background: #1d4ed8; color: #fff; font-weight: 650; cursor: pointer; }
    button:disabled { opacity: .6; cursor: default; }
    .error { color: #b91c1c; margin-top: 14px; }
    .muted { color: #475569; margin-top: 8px; font-size: .9rem; }
    code { background: #f1f5f9; padding: 1px 4px; border-radius: 4px; }
  `],
})
export class LoginComponent {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected email = '';
  protected password = '';
  protected readonly busy = signal(false);

  protected async submit(): Promise<void> {
    if (this.busy()) {
      return;
    }
    this.busy.set(true);
    try {
      await this.auth.login(this.email, this.password);

      // If we arrived here mid OAuth authorization-code flow (e.g. a ChatGPT/Claude connector),
      // establish the OAuth session cookie and hand the browser back to /connect/authorize.
      const returnUrl = this.route.snapshot.queryParamMap.get('returnUrl');
      if (returnUrl && returnUrl.startsWith('/connect/authorize')) {
        const target = await this.auth.createOAuthSession(returnUrl);
        window.location.assign(target);
        return;
      }

      await this.router.navigate([returnUrl && returnUrl.startsWith('/') ? returnUrl : '/items']);
    } catch {
      // error surfaced via auth.error()
    } finally {
      this.busy.set(false);
    }
  }
}
