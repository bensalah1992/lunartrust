import type { CheckResult } from '../../types/scan';

export async function checkSSL(hostname: string, signal: AbortSignal): Promise<CheckResult> {
  try {
    await fetch(`https://${hostname}`, { method: 'HEAD', redirect: 'manual', signal });
    return {
      id: 'ssl',
      label: 'SSL Certificate',
      summary: 'Valid',
      score: 'trusted',
      details: { Status: 'HTTPS active' },
    };
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      return {
        id: 'ssl',
        label: 'SSL Certificate',
        summary: 'Check timed out',
        score: 'warning',
        details: { Status: 'Timeout' },
      };
    }
    return {
      id: 'ssl',
      label: 'SSL Certificate',
      summary: 'No SSL — connection not encrypted',
      score: 'danger',
      details: { Status: 'No HTTPS' },
    };
  }
}
