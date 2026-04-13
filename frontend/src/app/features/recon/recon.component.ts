import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-recon',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="route-container">
      <header class="section-header">
        <div>
          <h2 class="t-heading">WEB_RECONNAISSANCE</h2>
          <span class="t-label">HEADLESS CRAWLER & TOPOLOGY</span>
        </div>
      </header>
      <div class="panel">
        <span class="t-label text-warning">[ MODULE IN DEVELOPMENT ]</span>
        <p style="margin-top: 1rem;">This module will handle network graphing and headless screenshots.</p>
      </div>
    </div>
  `,
  styles: [`
    .section-header {
      border-bottom: 1px solid var(--border);
      padding-bottom: var(--space-md);
      margin-bottom: var(--space-xl);
    }
    .panel {
      padding: var(--space-lg);
      border: 1px solid var(--border-visible);
      background-color: var(--surface);
    }
  `]
})
export class ReconComponent {}
