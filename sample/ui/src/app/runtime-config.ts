export interface FirebaseClientConfig {
  apiKey: string;
  authDomain: string;
  projectId: string;
  appId: string;
}

export interface OAuthClientConfig {
  clientId: string;
  tokenEndpoint: string;
  revocationEndpoint: string;
  scope: string;
}

export interface AppRuntimeConfig {
  firebase: FirebaseClientConfig;
  oauth: OAuthClientConfig;
  applicationInsightsConnectionString?: string;
}

/** Holds the runtime configuration fetched from /config.json before bootstrap. */
export const APP_CONFIG: { value: AppRuntimeConfig } = { value: undefined as unknown as AppRuntimeConfig };

export async function loadAppConfig(): Promise<AppRuntimeConfig> {
  const response = await fetch('/config.json', { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`Failed to load /config.json: HTTP ${response.status}`);
  }
  APP_CONFIG.value = (await response.json()) as AppRuntimeConfig;
  return APP_CONFIG.value;
}
