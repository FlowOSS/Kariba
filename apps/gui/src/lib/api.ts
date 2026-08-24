import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  QuarantineItem,
  ScanProgress,
  ScanResult,
  ScanHistoryItem,
  Detection,
  StatusResult,
  SurveyReport,
  Settings,
} from "./types";

export function daemonStatus(): Promise<StatusResult> {
  return invoke<StatusResult>("daemon_status");
}

export function survey(): Promise<SurveyReport> {
  return invoke<SurveyReport>("survey");
}

export function scan(
  paths: string[],
  quarantine: boolean,
  kind: string,
): Promise<ScanResult> {
  return invoke<ScanResult>("scan", { paths, quarantine, kind });
}

export function scanCancel(scanId: number): Promise<number> {
  return invoke<number>("scan_cancel", { scanId });
}

export function scanHistory(): Promise<ScanHistoryItem[]> {
  return invoke<ScanHistoryItem[]>("scan_history");
}

export function quarantineList(): Promise<QuarantineItem[]> {
  return invoke<QuarantineItem[]>("quarantine_list");
}

export function quarantineRestore(id: number): Promise<string> {
  return invoke<string>("quarantine_restore", { id });
}

export function quarantineDelete(id: number): Promise<boolean> {
  return invoke<boolean>("quarantine_delete", { id });
}

export function settingsGet(): Promise<Settings> {
  return invoke<Settings>("settings_get");
}

export function settingsSet(settings: Settings): Promise<Settings> {
  return invoke<Settings>("settings_set", { settings });
}

export function onScanProgress(cb: (p: ScanProgress) => void): Promise<UnlistenFn> {
  return listen<ScanProgress>("kariba://scan-progress", (event) => cb(event.payload));
}

export function onScanDetection(cb: (d: Detection) => void): Promise<UnlistenFn> {
  return listen<Detection>("kariba://scan-detection", (event) => cb(event.payload));
}
