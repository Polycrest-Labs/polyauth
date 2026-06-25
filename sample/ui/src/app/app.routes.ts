import { Routes } from '@angular/router';
import { authGuard } from './auth/auth.guard';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'items' },
  { path: 'sign-in', loadComponent: () => import('./login/login.component').then((m) => m.LoginComponent) },
  {
    path: 'items',
    canActivate: [authGuard],
    loadComponent: () => import('./items/items.component').then((m) => m.ItemsComponent),
  },
  { path: '**', redirectTo: 'items' },
];
