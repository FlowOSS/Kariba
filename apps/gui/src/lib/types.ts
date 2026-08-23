export type CheckStatus = "Ok" | "Warning" | "Failed";

export interface CheckResult {
  engine: string;
  component: string;
  status: CheckStatus;
  detail: string;
  suggestion: string | null;
}

export interface Distro {
  id: string;
  id_like: string[];
  name: string;
  pretty_name: string;
  family: string;
}

export interface SurveyReport {
  distro: Distro;
  init: string;
  checks: CheckResult[];
}

export interface StatusResult {
  daemon_version: string;
  uptime_secs: number;
  scans_total: number;
  threats_total: number;
  quarantined_items: number;
}

export interface ScanProgress {
  scan_id: number;
  files_scanned: number;
  threats_found: number;
  current: string;
}

export interface Detection {
  path: string;
  engine: string;
  signature: string;
}

export interface ScanResult {
  scan_id: number;
  files_scanned: number;
  threats_found: number;
  quarantined: number;
  duration_ms: number;
}

export interface QuarantineItem {
  id: number;
  original_path: string;
  engine: string;
  signature: string;
  size: number;
  quarantined_at: number;
}

export type View = "dashboard" | "scan" | "quarantine" | "survey";
