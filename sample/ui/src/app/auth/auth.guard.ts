import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './auth.service';

export const authGuard: CanActivateFn = async () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  // Wait for the initial Firebase auth-state restore so a refresh doesn't bounce a signed-in user.
  return (await auth.waitUntilReady()) ? true : router.createUrlTree(['/sign-in']);
};
