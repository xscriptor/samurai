import { Component, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-scanner',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './scanner.component.html',
  styleUrls: ['./scanner.component.scss']
})
export class ScannerComponent implements OnDestroy {
  targetDomain = 'scanme.nmap.org';
  isScanning = false;
  socket: WebSocket | null = null;
  terminalLogs: string[] = ['[ SYSTEM READY ] Waiting for target config...'];

  vulnerabilitiesFound = 0;

  constructor(private cdr: ChangeDetectorRef) {}

  initiateScan() {
    if (this.isScanning) return;
    if (!this.targetDomain) return;

    this.isScanning = true;
    this.terminalLogs = [`[+] CONNECTING TO ENGINE FOR SCANNING: ${this.targetDomain}...`];
    this.vulnerabilitiesFound = 0;
    this.cdr.detectChanges();

    const wsUrl = `ws://${window.location.hostname}:8000/api/scan/live?target=${encodeURIComponent(this.targetDomain)}`;
    this.socket = new WebSocket(wsUrl);

    this.socket.onmessage = (event) => {
      console.log("WS SCAN MESSAGE:", event.data);
      this.terminalLogs.push(event.data);
      if (event.data.includes('open')) {
        this.vulnerabilitiesFound++;
      }
      this.cdr.detectChanges();
    };

    this.socket.onclose = () => {
      console.log("WS SCAN CLOSED");
      this.terminalLogs.push('[!] CONNECTION CLOSED. Scan finished.');
      this.isScanning = false;
      this.cdr.detectChanges();
    };

    this.socket.onerror = (err) => {
      console.log("WS SCAN ERROR:", err);
      this.terminalLogs.push('[!] WEBSOCKET CONNECTION ERROR.');
      this.isScanning = false;
      this.cdr.detectChanges();
    };
  }

  ngOnDestroy() {
    if (this.socket) {
      this.socket.close();
    }
  }
}
