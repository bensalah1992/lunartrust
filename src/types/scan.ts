export type ScoreLevel = 'trusted' | 'warning' | 'danger' | 'unknown';

export type CheckId = 'ssl' | 'safebrowsing' | 'wayback' | 'domainAge' | 'heuristics';

export interface CheckResult {
  id: CheckId;
  label: string;
  summary: string;
  score: ScoreLevel;
  details: Record<string, string>;
}

export interface ScanResult {
  url: string;
  domain: string;
  score: ScoreLevel;
  headline: string;
  subline: string;
  checks: CheckResult[];
}
