import { Component, EventEmitter, Input, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-vuln-target-config',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './target-config.component.html',
  styleUrls: ['./target-config.component.scss']
})
export class VulnerabilitiesTargetConfigComponent {
  @Input() isScanning = false;
  @Input() targetUrl = '';
  @Input() activeModules: Record<string, boolean> = {};
  @Input() moduleOptions: Array<{ key: string; label: string; description: string }> = [];

  @Output() targetUrlChange = new EventEmitter<string>();
  @Output() initiate = new EventEmitter<void>();
  @Output() moduleToggle = new EventEmitter<string>();
}
