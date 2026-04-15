import { CommonModule } from '@angular/common';
import { Component, EventEmitter, Input, Output } from '@angular/core';

@Component({
  selector: 'app-recon-export-actions',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './recon-export-actions.component.html',
  styleUrls: ['./recon-export-actions.component.scss']
})
export class ReconExportActionsComponent {
  @Input() hasExports = false;

  @Output() exportCsv = new EventEmitter<void>();
  @Output() exportJson = new EventEmitter<void>();
  @Output() exportPdf = new EventEmitter<void>();
  @Output() exportBinary = new EventEmitter<void>();
}
