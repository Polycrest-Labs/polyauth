import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { App } from './app/app';
import { loadAppConfig } from './app/runtime-config';

loadAppConfig()
  .then(() => bootstrapApplication(App, appConfig))
  .catch((err) => {
    console.error('Failed to load runtime configuration.', err);
    const root = document.querySelector('app-root');
    if (root) {
      root.textContent = 'Failed to load runtime configuration. Check /config.json.';
    }
  });
