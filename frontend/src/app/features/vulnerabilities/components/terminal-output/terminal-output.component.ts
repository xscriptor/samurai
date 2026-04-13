import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-vuln-terminal-output',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './terminal-output.component.html',
  styleUrls: ['./terminal-output.component.scss']
})
export class VulnerabilitiesTerminalOutputComponent {
  @Input() title = 'DAST_ENGINE_STDOUT';
  @Input() terminalLogs: string[] = [];
  @Input() isScanning = false;
}
