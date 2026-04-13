export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  id: number;
  scan_id: number;
  link_id: number | null;
  severity: SeverityLevel;
  finding_type: string;
  description: string;
  cvss_score: string | null;
  poc_payload: string | null;
}

export interface DiscoveredLink {
  id: number;
  scan_id: number;
  url: string;
  status_code: number;
  content_type: string;
  findings: Finding[];
}

export interface ScanDetail {
  id: number;
  domain_target: string;
  status: string;
  scan_type: string;
  created_at: string;
  findings?: Finding[];
  discovered_links: DiscoveredLink[];
}

export interface ScanListItem {
  id: number;
  created_at?: string;
}

export interface TrendSnapshot {
  id: number;
  riskScore: number;
  totalFindings: number;
  label: string;
}

export interface AnalysisSummary {
  totalLinks: number;
  vulnerableLinks: number;
  cleanLinks: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  coveragePct: number;
  riskScore: number;
  avgFindingsPerLink: string;
  terminalEvents: number;
}
