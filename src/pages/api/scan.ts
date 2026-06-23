import type { APIRoute } from 'astro';
import type { CheckResult } from '../../types/scan';
import { checkSSL } from '../../lib/checks/ssl';
import { checkDomainAge } from '../../lib/checks/domainAge';
import { checkWayback } from '../../lib/checks/wayback';
import { checkSafeBrowsing } from '../../lib/checks/safebrowsing';
import { checkHeuristics } from '../../lib/checks/heuristics';

export const prerender = false;

const TIMEOUT_MS = 8000;

const CHECK_IDS = ['ssl', 'domainAge', 'heuristics', 'safebrowsing', 'wayback'] as const;

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export const GET: APIRoute = async ({ url: reqUrl }) => {
  const rawUrl = reqUrl.searchParams.get('url');

  if (!rawUrl) {
    return json({ error: 'invalid_url' }, 400);
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(rawUrl);
  } catch {
    return json({ error: 'invalid_url' }, 400);
  }

  const hostname = targetUrl.hostname;
  if (!hostname.includes('.')) {
    return json({ error: 'invalid_url' }, 400);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const results = await Promise.allSettled([
      checkSSL(hostname, controller.signal),
      checkDomainAge(hostname, controller.signal),
      checkHeuristics(rawUrl),
      checkSafeBrowsing(rawUrl, controller.signal),
      checkWayback(hostname, controller.signal),
    ]);

    const checks: CheckResult[] = results.map((r, i) => {
      if (r.status === 'fulfilled') return r.value;
      return {
        id: CHECK_IDS[i],
        label: CHECK_IDS[i],
        summary: 'Check unavailable',
        score: 'unknown' as const,
        details: { Status: 'Unavailable' },
      };
    });

    return json({ checks });
  } finally {
    clearTimeout(timer);
  }
};
