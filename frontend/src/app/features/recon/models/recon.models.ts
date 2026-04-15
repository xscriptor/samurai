export type ReconModuleId = 'dns' | 'subdomains' | 'apis' | 'headers' | 'tech' | 'all';

export interface ReconModule {
  id: ReconModuleId;
  label: string;
  icon: string;
  description: string;
}

export type ReconResultsViewId =
  | 'all'
  | 'surface-map'
  | 'dns'
  | 'subdomains'
  | 'apis'
  | 'auth-session'
  | 'headers'
  | 'client-side'
  | 'tech';

export interface ReconResultsViewOption {
  id: ReconResultsViewId;
  label: string;
}

export interface ReconEnvelope {
  type: 'RECON_COMPLETE' | 'RECON_ERROR';
  target: string;
  timestamp: string;
  results?: ReconResults;
  error?: string;
}

export interface ReconResults {
  dns?: Record<string, string[]>;
  subdomains?: {
    total_found: number;
    active: Record<string, string[]>;
    discovered_count: number;
    active_count?: number;
    discovered_hosts?: string[];
  };
  apis?: {
    apis_found: Array<{
      path: string;
      status: number;
      content_type: string;
    }>;
    documentation: string[];
    framework: string | null;
    headers_analysis: Record<string, string>;
    graphql_enabled: boolean;
    base_url?: string;
    probed_paths?: number;
  };
  headers?: {
    present: Record<string, { value: string; description: string }>;
    missing: string[];
    risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
    recommendations: string[];
  };
  technology?: {
    frontend: string[];
    backend: string[];
    cdn: string | null;
    interesting_findings: string[];
  };
}

export interface ReconState {
  targetDomain: string;
  selectedModules: ReconModuleId[];
  isScanning: boolean;
  terminalLines: string[];
  results: ReconResults | null;
}
