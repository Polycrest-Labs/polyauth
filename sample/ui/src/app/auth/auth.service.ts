import { Injectable, computed, signal } from '@angular/core';
import { initializeApp, getApps, FirebaseApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword, signOut, onAuthStateChanged, Auth, User } from 'firebase/auth';
import { APP_CONFIG } from '../runtime-config';

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  token_type: string;
}

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly app: FirebaseApp | null;
  private readonly auth: Auth | null;

  private readonly token = signal<string | null>(null);
  private refreshToken: string | null = null;
  private expiresAt = 0;

  readonly user = signal<User | null>(null);
  readonly isAuthenticated = computed(() => this.user() !== null && this.token() !== null);
  readonly error = signal<string | null>(null);

  /** Set when the Firebase web config (/config.json) is missing/invalid; the SPA shows a notice instead of a blank screen. */
  readonly configError = signal<string | null>(null);

  // Resolves after the first Firebase auth-state callback, so a page refresh can restore the session
  // before the route guard decides whether to allow a protected route.
  private resolveReady!: () => void;
  private readonly ready = new Promise<void>((resolve) => (this.resolveReady = resolve));

  constructor() {
    let app: FirebaseApp | null = null;
    let auth: Auth | null = null;
    try {
      const config = APP_CONFIG.value?.firebase;
      if (!config?.apiKey) {
        // Explicit check in case getAuth is lazy and doesn't throw synchronously on a placeholder config.
        throw new Error('Firebase web config missing (apiKey).');
      }
      app = getApps().length > 0 ? getApps()[0] : initializeApp(config);
      auth = getAuth(app);
    } catch (err) {
      // e.g. auth/invalid-api-key when the Firebase web config in /config.json is a placeholder.
      // Without this guard getAuth throws synchronously and, because the route guard injects this
      // service, the whole SPA (even /sign-in) renders blank.
      console.error('Firebase initialization failed; sign-in is unavailable.', err);
      this.configError.set('Authentication is not configured. Set the Firebase web config in /config.json.');
    }

    this.app = app;
    this.auth = auth;

    if (!auth) {
      this.resolveReady(); // unblock the route guard; the app stays unauthenticated
      return;
    }

    onAuthStateChanged(auth, async (firebaseUser) => {
      try {
        if (firebaseUser && this.token() === null) {
          // Firebase restored a session on reload — re-obtain an OAuth token for the API.
          await this.exchangeFirebaseToken();
          this.user.set(firebaseUser);
        } else if (!firebaseUser) {
          this.user.set(null);
          this.token.set(null);
        }
      } catch {
        this.user.set(null);
        this.token.set(null);
      } finally {
        this.resolveReady();
      }
    });
  }

  /** Awaits the initial Firebase auth-state restore, then reports whether the user is authenticated. */
  async waitUntilReady(): Promise<boolean> {
    await this.ready;
    return this.isAuthenticated();
  }

  async login(email: string, password: string): Promise<void> {
    if (!this.auth) {
      this.error.set(this.configError() ?? 'Authentication is not configured.');
      return;
    }
    this.error.set(null);
    try {
      const result = await signInWithEmailAndPassword(this.auth, email.trim(), password);
      await this.exchangeFirebaseToken();
      this.user.set(result.user);
    } catch (err) {
      this.error.set(this.format(err));
      throw err;
    }
  }

  /**
   * Establishes the interactive OAuthSession cookie from the current Firebase login so the
   * authorization-code flow (e.g. a ChatGPT/Claude connector) can continue. Returns the normalized
   * return URL to redirect the browser to (typically back to /connect/authorize).
   */
  async createOAuthSession(returnUrl: string): Promise<string> {
    const currentUser = this.auth?.currentUser;
    if (!currentUser) {
      throw new Error('Not signed in.');
    }
    const idToken = await currentUser.getIdToken();
    const response = await fetch('/api/oauth/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${idToken}` },
      body: JSON.stringify({ returnUrl }),
    });
    if (!response.ok) {
      throw new Error(`OAuth session login failed: HTTP ${response.status}`);
    }
    const data = (await response.json()) as { returnUrl: string };
    return data.returnUrl;
  }

  async logout(): Promise<void> {
    if (this.auth) {
      await signOut(this.auth);
    }
    this.user.set(null);
    this.token.set(null);
    this.refreshToken = null;
    this.expiresAt = 0;
  }

  /** Returns a valid OAuth access token, re-exchanging the Firebase ID token if expired. */
  async getAccessToken(): Promise<string | null> {
    const current = this.token();
    if (current && Date.now() < this.expiresAt - 30_000) {
      return current;
    }

    if (this.auth?.currentUser) {
      await this.exchangeFirebaseToken();
      return this.token();
    }

    return null;
  }

  private async exchangeFirebaseToken(): Promise<void> {
    const currentUser = this.auth?.currentUser;
    if (!currentUser) {
      throw new Error('Not signed in.');
    }
    const oauth = APP_CONFIG.value.oauth;
    const idToken = await currentUser.getIdToken();

    const body = new URLSearchParams({
      grant_type: 'urn:polyauth:firebase',
      client_id: oauth.clientId,
      firebase_id_token: idToken,
      scope: oauth.scope,
    });

    const response = await fetch(oauth.tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (!response.ok) {
      throw new Error(`Token exchange failed: HTTP ${response.status}`);
    }

    const token = (await response.json()) as TokenResponse;
    this.token.set(token.access_token);
    this.refreshToken = token.refresh_token ?? null;
    this.expiresAt = Date.now() + token.expires_in * 1000;
  }

  private format(err: unknown): string {
    const code = (err as { code?: string })?.code;
    switch (code) {
      case 'auth/invalid-credential':
      case 'auth/wrong-password':
      case 'auth/user-not-found':
        return 'Invalid email or password.';
      case 'auth/too-many-requests':
        return 'Too many attempts. Try again later.';
      default:
        return 'Sign-in failed. Please try again.';
    }
  }
}
