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
  protection_enabled: boolean;
  realtime_active: boolean;
  realtime_detail: string;
}

export interface RealtimeDetection {
  path: string;
  engine: string;
  signature: string;
  action: string;
}

export interface RealtimeSettings {
  enabled: boolean;
  auto_quarantine: boolean;
}

export interface ScanSettings {
  default_quarantine: boolean;
}

export interface ExclusionSettings {
  paths: string[];
  extensions: string[];
}

export interface Settings {
  realtime: RealtimeSettings;
  scan: ScanSettings;
  exclusions: ExclusionSettings;
}

export const BUILTIN_EXCLUSION_PATHS = ["/proc", "/sys", "/dev", "/run"];

export interface ScanProgress {
  scan_id: number;
  files_scanned: number;
  files_total: number;
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

export type ScanKind = "quick" | "full" | "custom";

export interface ScanHistoryItem {
  id: number;
  kind: string;
  paths: string[];
  started_at: number;
  finished_at: number | null;
  files_scanned: number;
  threats_found: number;
  status: string;
}

export interface QuarantineItem {
  id: number;
  original_path: string;
  engine: string;
  signature: string;
  size: number;
  quarantined_at: number;
  source: string;
}

export interface ThreatHistoryItem {
  id: number;
  path: string;
  sha256: string;
  engine: string;
  signature: string;
  detected_at: number;
  status: string;
  source: string;
}

export type View = "dashboard" | "scan" | "quarantine" | "survey" | "settings";
