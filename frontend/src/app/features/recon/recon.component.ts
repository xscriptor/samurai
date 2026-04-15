import { ChangeDetectorRef, Component, OnDestroy, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { ActivatedRoute } from '@angular/router';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { gzip } from 'pako';
import { ReconControlsComponent } from './components/controls/recon-controls.component';
import { ReconTerminalComponent } from './components/terminal/recon-terminal.component';
import { ReconResultsComponent } from './components/results/recon-results.component';
import { ReconExportActionsComponent } from './components/export-actions/recon-export-actions.component';
import { ReconEnvelope, ReconModule, ReconModuleId, ReconResults } from './models/recon.models';
import { ReconLiveService } from './services/recon-live.service';

interface ReconHistoryFinding {
  finding_type: string;
  poc_payload?: string | null;
}

interface ReconHistoryScanDetail {
  id: number;
  domain_target: string;
  status: string;
  scan_type: string;
  findings?: ReconHistoryFinding[];
}

interface ReconExportRow {
  section: string;
  item: string;
  status: string;
  details: string;
}

@Component({
  selector: 'app-recon',
  standalone: true,
  imports: [CommonModule, ReconControlsComponent, ReconTerminalComponent, ReconResultsComponent, ReconExportActionsComponent],
  templateUrl: './recon.component.html',
  styleUrl: './recon.component.scss'
})
export class ReconComponent implements OnInit, OnDestroy {
  targetDomain: string = '';
  isScanning: boolean = false;
  terminalLines: string[] = [];
  reconResults: ReconResults | null = null;
  selectedModules: ReconModuleId[] = ['all'];
  private destroyed = false;

  reconModules: ReconModule[] = [
    {
      id: 'dns',
      label: 'DNS',
      icon: 'D',
      description: 'DNS enumeration (A, AAAA, MX, NS, TXT, SOA)'
    },
    {
      id: 'subdomains',
      label: 'SUBDOMAINS',
      icon: 'S',
      description: 'Enumerate subdomains via Certificate Transparency'
    },
    {
      id: 'apis',
      label: 'APIs',
      icon: 'A',
      description: 'Discover API endpoints and documentation'
    },
    {
      id: 'headers',
      label: 'HEADERS',
      icon: 'H',
      description: 'Analyze security headers and configurations'
    },
    {
      id: 'tech',
      label: 'TECH STACK',
      icon: 'T',
      description: 'Identify frontend & backend technologies'
    }
  ];

  constructor(
    private reconLiveService: ReconLiveService,
    private cdr: ChangeDetectorRef,
    private http: HttpClient,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    this.route.queryParamMap.subscribe((params) => {
      const scanId = Number(params.get('scanId'));
      if (Number.isInteger(scanId) && scanId > 0) {
        this.loadReconFromHistory(scanId);
      }
    });
  }

  ngOnDestroy() {
    this.destroyed = true;
    this.reconLiveService.disconnect();
  }

  updateTargetDomain(value: string): void {
    this.targetDomain = value;
  }

  toggleModule(moduleId: ReconModuleId) {
    const index = this.selectedModules.indexOf(moduleId);
    if (index > -1) {
      this.selectedModules.splice(index, 1);
    } else {
      if (this.selectedModules.includes('all') && moduleId !== 'all') {
        this.selectedModules = [];
      }
      if (moduleId === 'all') {
        this.selectedModules = ['all'];
      } else {
        this.selectedModules.push(moduleId);
      }
    }

    if (this.selectedModules.length === 0) {
      this.selectedModules = ['all'];
    }
  }

  selectPreset(preset: 'all' | 'basic' | 'api') {
    if (preset === 'all') {
      this.selectedModules = ['all'];
    } else if (preset === 'basic') {
      this.selectedModules = ['dns', 'headers'];
    } else if (preset === 'api') {
      this.selectedModules = ['apis', 'tech'];
    }
  }

  clearTerminal() {
    this.terminalLines = [];
    this.reconResults = null;
  }

  startRecon() {
    if (!this.targetDomain || this.isScanning) return;

    this.isScanning = true;
    this.terminalLines = [];
    this.reconResults = null;

    this.reconLiveService.connect(this.targetDomain, this.selectedModules, {
      onLog: (line) => this.addTerminalLine(line),
      onComplete: (message: ReconEnvelope) => {
        this.reconResults = message.results || null;
        this.addTerminalLine('[done] reconnaissance complete');
        this.isScanning = false;
        this.safeDetectChanges();
      },
      onError: (message) => {
        this.addTerminalLine(`[error] ${message}`);
        this.isScanning = false;
        this.safeDetectChanges();
      },
      onUnexpectedClose: () => {
        if (this.isScanning) {
          this.addTerminalLine('[error] websocket closed unexpectedly');
          this.isScanning = false;
          this.safeDetectChanges();
        }
      }
    });
  }

  exportReconAsJson(): void {
    const payload = this.buildReconExportPayload();
    this.downloadTextFile(
      `${this.buildReconFilePrefix()}.json`,
      JSON.stringify(payload, null, 2),
      'application/json'
    );
  }

  exportReconAsCsv(): void {
    const rows = this.flattenReconExportRows();
    const headers = ['section', 'item', 'status', 'details'];
    const csvLines = [headers.join(',')];

    rows.forEach((row) => {
      csvLines.push(headers.map((header) => this.escapeCsv(row[header as keyof ReconExportRow])).join(','));
    });

    this.downloadTextFile(`${this.buildReconFilePrefix()}.csv`, csvLines.join('\n'), 'text/csv;charset=utf-8');
  }

  exportReconAsPdf(): void {
    const rows = this.flattenReconExportRows();
    const payload = this.buildReconExportPayload();
    const doc = new jsPDF({ orientation: 'landscape', unit: 'pt', format: 'a4' });

    doc.setFontSize(14);
    doc.text('Samurai Web Recon Report', 40, 36);
    doc.setFontSize(10);
    doc.text(`Target: ${payload.target || 'unknown'}`, 40, 54);
    doc.text(`Modules: ${payload.selectedModules.join(', ')}`, 40, 68);
    doc.text(`Exported: ${payload.exportedAt}`, 40, 82);

    autoTable(doc, {
      startY: 96,
      head: [['Section', 'Item', 'Status', 'Details']],
      body: rows.map((row) => [row.section, row.item, row.status, row.details]),
      styles: { fontSize: 8, cellPadding: 3, overflow: 'linebreak' },
      headStyles: { fillColor: [35, 35, 35] }
    });

    doc.save(`${this.buildReconFilePrefix()}.pdf`);
  }

  exportReconAsBinary(): void {
    const payload = this.buildReconExportPayload();
    const bytes = gzip(JSON.stringify(payload));
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${this.buildReconFilePrefix()}.bin`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  private loadReconFromHistory(scanId: number): void {
    this.reconLiveService.disconnect();
    this.isScanning = false;

    this.http.get<ReconHistoryScanDetail>(`http://${window.location.hostname}:8000/api/scans/${scanId}`).subscribe({
      next: (detail) => {
        this.targetDomain = detail.domain_target || this.targetDomain;

        const reconFinding = (detail.findings || []).find(
          (finding) => String(finding.finding_type || '').toLowerCase() === 'web_recon_results'
        );

        if (!reconFinding?.poc_payload) {
          this.reconResults = null;
          this.selectedModules = ['all'];
          this.terminalLines = [
            `[history] report #${scanId} loaded`,
            '[history] no serialized recon payload found for this scan'
          ];
          this.safeDetectChanges();
          return;
        }

        try {
          const parsedResults = JSON.parse(reconFinding.poc_payload) as ReconResults;
          this.reconResults = parsedResults;
          this.selectedModules = this.resolveModulesFromResults(parsedResults);
          this.terminalLines = [
            `[history] report #${detail.id} restored (${detail.status})`,
            `[history] target=${detail.domain_target}`,
            '[history] recon results rehydrated from database'
          ];
        } catch {
          this.reconResults = null;
          this.selectedModules = ['all'];
          this.terminalLines = [
            `[history] report #${scanId} loaded`,
            '[error] failed to parse serialized recon payload'
          ];
        }

        this.safeDetectChanges();
      },
      error: () => {
        this.reconResults = null;
        this.selectedModules = ['all'];
        this.terminalLines = [`[error] unable to load recon report #${scanId}`];
        this.safeDetectChanges();
      }
    });
  }

  private resolveModulesFromResults(results: ReconResults): ReconModuleId[] {
    const modules: ReconModuleId[] = [];

    if (results.dns) {
      modules.push('dns');
    }
    if (results.subdomains) {
      modules.push('subdomains');
    }
    if (results.apis) {
      modules.push('apis');
    }
    if (results.headers) {
      modules.push('headers');
    }
    if (results.technology) {
      modules.push('tech');
    }

    return modules.length > 0 ? modules : ['all'];
  }

  private buildReconExportPayload() {
    return {
      target: this.targetDomain,
      selectedModules: this.selectedModules,
      exportedAt: new Date().toISOString(),
      terminalLines: [...this.terminalLines],
      results: this.reconResults,
      flattenedRows: this.flattenReconExportRows()
    };
  }

  private flattenReconExportRows(): ReconExportRow[] {
    const rows: ReconExportRow[] = [];
    const results = this.reconResults;

    if (!results) {
      return [
        {
          section: 'RECON',
          item: 'NO_RESULTS',
          status: 'EMPTY',
          details: 'No recon results available to export'
        }
      ];
    }

    const dns = results.dns || {};
    Object.entries(dns).forEach(([recordType, values]) => {
      if (values.length === 0) {
        rows.push({ section: 'DNS', item: recordType, status: 'NO_RECORD', details: '' });
      } else {
        values.forEach((value) => {
          rows.push({ section: 'DNS', item: recordType, status: 'FOUND', details: value });
        });
      }
    });

    const subdomains = results.subdomains;
    if (subdomains) {
      const activeMap = subdomains.active || {};
      const discovered = subdomains.discovered_hosts && subdomains.discovered_hosts.length > 0
        ? subdomains.discovered_hosts
        : Object.keys(activeMap);

      discovered.forEach((host) => {
        const ips = activeMap[host] || [];
        rows.push({
          section: 'SUBDOMAINS',
          item: host,
          status: ips.length > 0 ? 'ACTIVE' : 'PASSIVE',
          details: ips.join(' | ')
        });
      });
    }

    const apis = results.apis;
    if (apis) {
      apis.apis_found.forEach((endpoint) => {
        rows.push({
          section: 'API',
          item: endpoint.path,
          status: String(endpoint.status),
          details: endpoint.content_type || 'unknown'
        });
      });

      apis.documentation.forEach((docPath) => {
        rows.push({ section: 'API_DOCS', item: docPath, status: 'FOUND', details: '' });
      });

      rows.push({ section: 'API_META', item: 'BASE_URL', status: 'INFO', details: apis.base_url || 'unreachable' });
      rows.push({ section: 'API_META', item: 'FRAMEWORK', status: 'INFO', details: apis.framework || 'unknown' });
      rows.push({ section: 'API_META', item: 'PROBED_PATHS', status: 'INFO', details: String(apis.probed_paths || 0) });
    }

    const headers = results.headers;
    if (headers) {
      Object.entries(headers.present || {}).forEach(([name, value]) => {
        rows.push({
          section: 'HEADERS',
          item: name,
          status: 'PRESENT',
          details: `${value.value} | ${value.description}`
        });
      });

      (headers.missing || []).forEach((name) => {
        rows.push({ section: 'HEADERS', item: name, status: 'MISSING', details: '' });
      });

      (headers.recommendations || []).forEach((recommendation) => {
        rows.push({ section: 'HEADERS_RECOMMENDATION', item: 'ACTION', status: headers.risk_level, details: recommendation });
      });
    }

    const technology = results.technology;
    if (technology) {
      technology.frontend.forEach((entry) => {
        rows.push({ section: 'TECH_FRONTEND', item: entry, status: 'SIGNAL', details: '' });
      });
      technology.backend.forEach((entry) => {
        rows.push({ section: 'TECH_BACKEND', item: entry, status: 'SIGNAL', details: '' });
      });
      if (technology.cdn) {
        rows.push({ section: 'TECH_CDN', item: technology.cdn, status: 'SIGNAL', details: '' });
      }
      technology.interesting_findings.forEach((entry) => {
        rows.push({ section: 'TECH_FINDING', item: 'INTERESTING', status: 'INFO', details: entry });
      });
    }

    return rows.length > 0
      ? rows
      : [
          {
            section: 'RECON',
            item: 'NO_SIGNALS',
            status: 'EMPTY',
            details: 'Recon completed without collectible signals'
          }
        ];
  }

  private buildReconFilePrefix(): string {
    const target = this.sanitizeFileToken(this.targetDomain || 'unknown-target');
    return `samurai-recon-${target}`;
  }

  private sanitizeFileToken(value: string): string {
    return value
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9.-]+/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '') || 'unknown';
  }

  private escapeCsv(value: unknown): string {
    const raw = value === null || value === undefined ? '' : String(value);
    const escaped = raw.replace(/"/g, '""');
    return `"${escaped}"`;
  }

  private downloadTextFile(filename: string, content: string, mimeType: string): void {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  private safeDetectChanges(): void {
    if (!this.destroyed) {
      this.cdr.detectChanges();
    }
  }

  private addTerminalLine(line: string) {
    this.terminalLines.push(line);
    this.safeDetectChanges();

    setTimeout(() => {
      const terminal = document.querySelector('.terminal');
      if (terminal) {
        terminal.scrollTop = terminal.scrollHeight;
      }
    }, 0);
  }

}

