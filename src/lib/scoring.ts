import type { CheckResult, ScoreLevel, ScanResult } from '../types/scan';

const HEADLINES: Record<Exclude<ScoreLevel, 'unknown'>, string> = {
  trusted: 'This website appears safe',
  warning: 'Proceed with caution',
  danger: 'This website is dangerous',
};

export function computeScore(checks: CheckResult[]): Exclude<ScoreLevel, 'unknown'> {
  if (checks.some((c) => c.score === 'danger')) return 'danger';
  if (checks.some((c) => c.score === 'warning')) return 'warning';
  return 'trusted';
}

export function buildScanResult(url: string, checks: CheckResult[]): ScanResult {
  const domain = new URL(url).hostname;
  const score = computeScore(checks);
  const counted = checks.filter((c) => c.score !== 'unknown');
  const passed = counted.filter((c) => c.score === 'trusted').length;

  return {
    url,
    domain,
    score,
    headline: HEADLINES[score],
    subline: `${passed} of ${counted.length} checks passed`,
    checks,
  };
}
