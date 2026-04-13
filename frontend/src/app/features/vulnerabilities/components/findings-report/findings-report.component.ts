import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { DiscoveredLink, ScanDetail, SeverityLevel } from '../../models/vulnerabilities.models';

@Component({
  selector: 'app-vuln-findings-report',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './findings-report.component.html',
  styleUrls: ['./findings-report.component.scss']
})
export class VulnerabilitiesFindingsReportComponent {
  @Input() completedScanDetails: ScanDetail | null = null;

  severityFilter: 'all' | SeverityLevel = 'all';
  typeFilter = 'all';

  get availableTypes() {
    if (!this.completedScanDetails) return [];
    const types = new Set<string>();
    this.completedScanDetails.discovered_links.forEach((link) => {
      (link.findings || []).forEach((finding) => types.add(finding.finding_type));
    });
    return Array.from(types).sort();
  }

  get filteredLinks() {
    if (!this.completedScanDetails) return [];
    return this.completedScanDetails.discovered_links
      .map((link) => ({
        ...link,
        findings: (link.findings || []).filter((finding) => {
          const severityOk = this.severityFilter === 'all' || finding.severity === this.severityFilter;
          const typeOk = this.typeFilter === 'all' || finding.finding_type === this.typeFilter;
          return severityOk && typeOk;
        })
      }))
      .filter((link) => link.findings.length > 0 || (this.severityFilter === 'all' && this.typeFilter === 'all'));
  }

  get hasActiveFilters() {
    return this.severityFilter !== 'all' || this.typeFilter !== 'all';
  }

  resetFilters() {
    this.severityFilter = 'all';
    this.typeFilter = 'all';
  }

  severityCount(links: DiscoveredLink[]) {
    return links.reduce((acc, link) => acc + (link.findings?.length || 0), 0);
  }
}
