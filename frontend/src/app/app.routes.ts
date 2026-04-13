import { Routes } from '@angular/router';

export const routes: Routes = [
    {
        path: 'scanner',
        loadComponent: () => import('./features/scanner/scanner.component').then(m => m.ScannerComponent)
    },
    {
        path: 'recon',
        loadComponent: () => import('./features/recon/recon.component').then(m => m.ReconComponent)
    },
    {
        path: 'vulnerabilities',
        loadComponent: () => import('./features/vulnerabilities/vulnerabilities.component').then(m => m.VulnerabilitiesComponent)
    },
    {
        path: 'history',
        loadComponent: () => import('./features/history/history.component').then(m => m.HistoryComponent)
    },
    {
        path: '',
        redirectTo: '/scanner',
        pathMatch: 'full'
    }
];
