import { CommonModule } from '@angular/common';
import { Component, Input } from '@angular/core';
import { ReconResults, ReconResultsViewId } from '../../models/recon.models';
import { ReconApiResultsComponent } from './components/recon-api-results.component';
import { ReconDnsResultsComponent } from './components/recon-dns-results.component';
import { ReconHeadersResultsComponent } from './components/recon-headers-results.component';
import { ReconSubdomainsResultsComponent } from './components/recon-subdomains-results.component';
import { ReconTechResultsComponent } from './components/recon-tech-results.component';

@Component({
  selector: 'app-recon-results',
  standalone: true,
  imports: [
    CommonModule,
    ReconDnsResultsComponent,
    ReconSubdomainsResultsComponent,
    ReconApiResultsComponent,
    ReconHeadersResultsComponent,
    ReconTechResultsComponent
  ],
  templateUrl: './recon-results.component.html',
  styleUrl: './recon-results.component.scss'
})
export class ReconResultsComponent {
  @Input() results: ReconResults | null = null;
  @Input() targetDomain: string = '';
  @Input() activeFilter: ReconResultsViewId = 'all';

  private readonly authSessionHeaders = new Set([
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'set-cookie'
  ]);

  private readonly clientSignalPattern = /(script|\.js|bundle|chunk|webpack|vite|sourcemap|source map|asset|static|cdn)/i;
  private readonly clientRoutePattern = /(^\/(assets|static|js|dist|public|client|frontend)|\.js$|\.map$|manifest\.json|service-worker|sw\.js)/i;

  readonly filterLabels: Record<ReconResultsViewId, string> = {
    all: 'ALL',
    'surface-map': 'SURFACE MAP',
    dns: 'DNS',
    subdomains: 'SUBDOMAINS',
    apis: 'API',
    'auth-session': 'AUTH/SESSION',
    headers: 'HEADERS',
    'client-side': 'CLIENT SIDE',
    tech: 'TECH STACK'
  };

  hasAnyResults(): boolean {
    return this.availableSections() > 0;
  }

  availableSections(): number {
    if (!this.results) {
      return 0;
    }

    const sections = [
      this.hasContent(this.results.dns),
      this.hasContent(this.results.subdomains),
      this.hasContent(this.results.apis),
      this.hasContent(this.results.headers),
      this.hasContent(this.results.technology),
      this.surfaceMapHasContent(),
      this.authSessionHasContent(),
      this.clientSideHasContent()
    ];

    return sections.filter(Boolean).length;
  }

  totalSections(): number {
    return 8;
  }

  isAllView(): boolean {
    return this.activeFilter === 'all';
  }

  shouldShow(section: Exclude<ReconResultsViewId, 'all'>): boolean {
    return this.activeFilter === 'all' || this.activeFilter === section;
  }

  activeFilterLabel(): string {
    return this.filterLabels[this.activeFilter] || 'ALL';
  }

  dnsTotal(): number {
    return Object.values(this.results?.dns || {}).reduce((total, records) => total + records.length, 0);
  }

  subdomainTotal(): number {
    const subdomains = this.results?.subdomains;
    if (!subdomains) {
      return 0;
    }

    return subdomains.total_found || subdomains.discovered_count || 0;
  }

  subdomainActiveTotal(): number {
    const subdomains = this.results?.subdomains;
    if (!subdomains) {
      return 0;
    }

    return subdomains.active_count ?? Object.keys(subdomains.active || {}).length;
  }

  apiTotal(): number {
    return this.results?.apis?.apis_found.length || 0;
  }

  apiProbeTotal(): number {
    return this.results?.apis?.probed_paths || 0;
  }

  documentationTotal(): number {
    return this.results?.apis?.documentation.length || 0;
  }

  headerPresentTotal(): number {
    return Object.keys(this.results?.headers?.present || {}).length;
  }

  headerMissingTotal(): number {
    return this.results?.headers?.missing.length || 0;
  }

  techSignalTotal(): number {
    const tech = this.results?.technology;
    if (!tech) {
      return 0;
    }

    return tech.frontend.length + tech.backend.length + (tech.cdn ? 1 : 0) + tech.interesting_findings.length;
  }

  surfaceHosts(): string[] {
    const hosts = new Set<string>();
    const normalizedTarget = this.targetDomain.trim().toLowerCase();
    const discoveredHosts = this.results?.subdomains?.discovered_hosts || [];
    const activeHosts = Object.keys(this.results?.subdomains?.active || {});

    if (normalizedTarget) {
      hosts.add(normalizedTarget);
    }

    discoveredHosts.forEach((host) => {
      if (host) {
        hosts.add(host.trim().toLowerCase());
      }
    });

    activeHosts.forEach((host) => {
      if (host) {
        hosts.add(host.trim().toLowerCase());
      }
    });

    return Array.from(hosts).sort();
  }

  surfaceEndpoints(): string[] {
    const endpointSignals = [
      ...(this.results?.apis?.apis_found || []).map((endpoint) => endpoint.path),
      ...(this.results?.apis?.documentation || [])
    ];

    return this.uniqueSignals(endpointSignals);
  }

  surfaceTechSignals(): string[] {
    const technology = this.results?.technology;

    if (!technology) {
      return [];
    }

    const signals = [...technology.frontend, ...technology.backend, ...technology.interesting_findings];

    if (technology.cdn) {
      signals.push(`CDN: ${technology.cdn}`);
    }

    return this.uniqueSignals(signals);
  }

  surfaceMapHasContent(): boolean {
    const discoveredHosts = this.results?.subdomains?.discovered_hosts?.length || 0;
    const activeHosts = Object.keys(this.results?.subdomains?.active || {}).length;
    const endpoints = this.surfaceEndpoints().length;
    const techSignals = this.surfaceTechSignals().length;

    return discoveredHosts + activeHosts + endpoints + techSignals > 0;
  }

  authSessionPresentControls(): string[] {
    const presentHeaders = Object.keys(this.results?.headers?.present || {});
    const apiHeaderSignals = Object.keys(this.results?.apis?.headers_analysis || {});
    const controls = [...presentHeaders, ...apiHeaderSignals].filter((headerName) => this.isAuthSessionControl(headerName));

    return this.uniqueSignals(controls).map((headerName) => headerName.toUpperCase());
  }

  authSessionMissingControls(): string[] {
    const missingHeaders = (this.results?.headers?.missing || []).filter((headerName) =>
      this.isAuthSessionControl(headerName)
    );

    return this.uniqueSignals(missingHeaders).map((headerName) => headerName.toUpperCase());
  }

  authSessionCookieSignals(): string[] {
    const cookieSignals: string[] = [];
    const presentHeaders = Object.entries(this.results?.headers?.present || {});

    presentHeaders.forEach(([name, descriptor]) => {
      if (name.toLowerCase().includes('cookie')) {
        cookieSignals.push(`${name}: ${descriptor.value}`);
      }
    });

    Object.entries(this.results?.apis?.headers_analysis || {}).forEach(([name, value]) => {
      if (name.toLowerCase().includes('cookie')) {
        cookieSignals.push(`${name}: ${value}`);
      }
    });

    return this.uniqueSignals(cookieSignals).slice(0, 6);
  }

  authSessionRiskLevel(): 'LOW' | 'MEDIUM' | 'HIGH' {
    const missingControls = this.authSessionMissingControls().length;
    const presentControls = this.authSessionPresentControls().length;

    if (missingControls >= 3 || (missingControls >= 1 && presentControls <= 1)) {
      return 'HIGH';
    }

    if (missingControls > 0) {
      return 'MEDIUM';
    }

    return 'LOW';
  }

  authSessionHasContent(): boolean {
    return (
      this.authSessionPresentControls().length > 0 ||
      this.authSessionMissingControls().length > 0 ||
      this.authSessionCookieSignals().length > 0
    );
  }

  clientSideFrameworkSignals(): string[] {
    return this.uniqueSignals(this.results?.technology?.frontend || []);
  }

  clientSideAssetSignals(): string[] {
    const findings = this.results?.technology?.interesting_findings || [];

    return this.uniqueSignals(findings.filter((entry) => this.clientSignalPattern.test(entry)));
  }

  clientSideRouteSignals(): string[] {
    const routeCandidates = [
      ...(this.results?.apis?.apis_found || []).map((endpoint) => endpoint.path),
      ...(this.results?.apis?.documentation || [])
    ];

    return this.uniqueSignals(routeCandidates.filter((path) => this.clientRoutePattern.test(path)));
  }

  clientSideWarnings(): string[] {
    const warnings: string[] = [];
    const missingHeaders = (this.results?.headers?.missing || []).map((header) => header.toLowerCase());

    if (missingHeaders.includes('content-security-policy')) {
      warnings.push('Missing CSP header can increase script injection risk in browser contexts.');
    }

    if (missingHeaders.includes('x-content-type-options')) {
      warnings.push('Missing X-Content-Type-Options can enable MIME-type confusion in some clients.');
    }

    if (this.clientSideAssetSignals().some((signal) => /source map|\.map/i.test(signal))) {
      warnings.push('Potential source-map exposure detected in passive frontend signals.');
    }

    if (warnings.length === 0 && !this.clientSideHasContent()) {
      warnings.push('No explicit client-side exposure signals were recovered from current probes.');
    }

    return warnings;
  }

  clientSideHasContent(): boolean {
    return (
      this.clientSideFrameworkSignals().length > 0 ||
      this.clientSideAssetSignals().length > 0 ||
      this.clientSideRouteSignals().length > 0
    );
  }

  riskClass(level: 'LOW' | 'MEDIUM' | 'HIGH'): string {
    return `risk-${level.toLowerCase()}`;
  }

  private isAuthSessionControl(headerName: string): boolean {
    return this.authSessionHeaders.has(headerName.toLowerCase());
  }

  private uniqueSignals(signals: string[]): string[] {
    const unique = new Set<string>();

    signals.forEach((signal) => {
      const normalized = signal.trim();
      if (normalized) {
        unique.add(normalized);
      }
    });

    return Array.from(unique);
  }

  private hasContent(section: unknown): boolean {
    if (!section) {
      return false;
    }

    if (Array.isArray(section)) {
      return section.length > 0;
    }

    if (typeof section === 'object') {
      return Object.values(section as Record<string, unknown>).some((value) => {
        if (Array.isArray(value)) {
          return value.length > 0;
        }

        if (value && typeof value === 'object') {
          return Object.keys(value as Record<string, unknown>).length > 0;
        }

        return value !== null && value !== undefined && value !== '';
      });
    }

    return true;
  }
}
