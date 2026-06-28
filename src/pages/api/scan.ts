import type { APIRoute } from 'astro';
import type { CheckResult } from '../../types/scan';
import { checkSSL } from '../../lib/checks/ssl';
import { checkDomainAge } from '../../lib/checks/domainAge';
import { checkWayback } from '../../lib/checks/wayback';
import { checkSafeBrowsing } from '../../lib/checks/safebrowsing';
import { checkHeuristics } from '../../lib/checks/heuristics';

export const prerender = false;

// ── Constants ────────────────────────────────────────────────────────────────

const TIMEOUT_MS = 8000;
const MAX_URL_LENGTH = 2048;
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

// ── In-memory rate limiter ───────────────────────────────────────────────────
// Per Worker instance (not globally shared across CF instances), but effective
// against burst abuse from a single IP hitting the same instance.
// CF Pages free plan has no persistent rate limiting primitive.

const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 10;
const RATE_MAP_CAP = 500;

type RateEntry = { count: number; resetAt: number };
const rateMap = new Map<string, RateEntry>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  if (rateMap.size >= RATE_MAP_CAP) {
    for (const [k, v] of rateMap) {
      if (now > v.resetAt) rateMap.delete(k);
    }
  }
  const entry = rateMap.get(ip);
  if (!entry || now > entry.resetAt) {
    rateMap.set(ip, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return false;
  }
  if (entry.count >= RATE_MAX) return true;
  entry.count++;
  return false;
}

// ── SSRF guard ───────────────────────────────────────────────────────────────
// CF Workers already blocks RFC1918 egress at the platform level, but explicit
// validation is defense-in-depth and documents intent.

function isPrivateOrReserved(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, ''); // strip IPv6 brackets

  if (h === 'localhost' || h.endsWith('.localhost') || h === 'broadcasthost') return true;
  if (h === 'metadata.google.internal') return true;

  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (a === 10 || a === 127 || a === 0) return true;             // 10/8, loopback, 0/8
    if (a === 169 && b === 254) return true;                       // link-local / AWS metadata
    if (a === 172 && b >= 16 && b <= 31) return true;             // 172.16/12
    if (a === 192 && b === 168) return true;                       // 192.168/16
  }

  // IPv6 loopback and ULA/link-local
  if (h === '::1' || h.startsWith('fc') || h.startsWith('fd') || h.startsWith('fe80')) return true;

  return false;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

const CHECK_IDS = ['ssl', 'domainAge', 'heuristics', 'safebrowsing', 'wayback'] as const;

function json(data: unknown, status = 200, extra?: Record<string, string>) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      ...extra,
    },
  });
}

// ── Handler ──────────────────────────────────────────────────────────────────

export const GET: APIRoute = async ({ url: reqUrl, request }) => {
  // 1. Origin check — if present, must match the serving Host.
  //    Blocks third-party pages from calling our API via browser fetch while
  //    still allowing direct/curl calls (no Origin header) and local dev.
  const origin = request.headers.get('Origin');
  if (origin) {
    const host = request.headers.get('Host') ?? '';
    const isLocal = host.startsWith('localhost') || host.startsWith('127.');
    const allowed = isLocal
      ? [`http://${host}`, `https://${host}`]
      : [`https://${host}`];
    if (!allowed.includes(origin)) {
      return json({ error: 'forbidden' }, 403);
    }
  }

  // 2. Rate limiting (CF-Connecting-IP is injected by Cloudflare, not spoofable by client)
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  if (isRateLimited(ip)) {
    return json({ error: 'rate_limited' }, 429, { 'Retry-After': '60' });
  }

  // 3. Input validation
  const rawUrl = reqUrl.searchParams.get('url');
  if (!rawUrl || rawUrl.length > MAX_URL_LENGTH) {
    return json({ error: 'invalid_url' }, 400);
  }

  let targetUrl: URL;
  try {
    targetUrl = new URL(rawUrl);
  } catch {
    return json({ error: 'invalid_url' }, 400);
  }

  // 4. Protocol allowlist — blocks ftp:, ws:, file:, javascript:, data:, etc.
  if (!ALLOWED_PROTOCOLS.has(targetUrl.protocol)) {
    return json({ error: 'invalid_url' }, 400);
  }

  const hostname = targetUrl.hostname;
  if (!hostname.includes('.')) {
    return json({ error: 'invalid_url' }, 400);
  }

  // 5. SSRF guard — explicit private address check (CF Workers also blocks these at infra level)
  if (isPrivateOrReserved(hostname)) {
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
