import type { CheckResult } from '../../types/scan';

type FetchResult =
  | { status: 'found'; value: string }
  | { status: 'not_found' }
  | { status: 'error' };

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), ms)
    ),
  ]);
}

function parseTimestamp(ts: string): string {
  return new Date(
    `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`
  ).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

async function fetchFirstSnapshot(domain: string, signal: AbortSignal): Promise<FetchResult> {
  try {
    const res = await withTimeout(
      fetch(
        `https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp`,
        { signal }
      ),
      4000
    );
    const data = await res.json();
    if (Array.isArray(data) && data.length >= 2) {
      return { status: 'found', value: parseTimestamp(data[1][0]) };
    }
    return { status: 'not_found' };
  } catch {
    return { status: 'error' };
  }
}

async function fetchLatestSnapshot(domain: string, signal: AbortSignal): Promise<FetchResult> {
  try {
    const res = await withTimeout(
      fetch(`https://archive.org/wayback/available?url=${domain}`, { signal }),
      4000
    );
    const data = await res.json();
    const ts = data?.archived_snapshots?.closest?.timestamp;
    if (ts) return { status: 'found', value: parseTimestamp(ts) };
    return { status: 'not_found' };
  } catch {
    return { status: 'error' };
  }
}

export async function checkWayback(hostname: string, signal: AbortSignal): Promise<CheckResult> {
  const domain = hostname.replace(/^www\./, '');

  const [first, latest] = await Promise.all([
    fetchFirstSnapshot(domain, signal),
    fetchLatestSnapshot(domain, signal),
  ]);

  // Both APIs unreachable — don't affect score
  if (first.status === 'error' && latest.status === 'error') {
    return {
      id: 'wayback',
      label: 'Wayback Machine',
      summary: 'Check unavailable',
      score: 'unknown',
      details: { Status: 'Unavailable' },
    };
  }

  // At least one API responded — no history found → genuine warning signal
  if (first.status !== 'found' && latest.status !== 'found') {
    return {
      id: 'wayback',
      label: 'Wayback Machine',
      summary: 'No archive history found',
      score: 'warning',
      details: { Status: 'Not archived' },
    };
  }

  const details: Record<string, string> = {};
  if (first.status === 'found') details['First seen'] = first.value;
  if (latest.status === 'found') details['Last snapshot'] = latest.value;

  return {
    id: 'wayback',
    label: 'Wayback Machine',
    summary: first.status === 'found' ? `First snapshot: ${first.value}` : 'Archive history found',
    score: 'trusted',
    details,
  };
}
