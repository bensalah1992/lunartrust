import type { CheckResult } from '../../types/scan';

type RdapData = {
  registered: Date;
  registrarName: string;
};

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), ms)
    ),
  ]);
}

function monthsSince(date: Date): number {
  const now = new Date();
  return (now.getFullYear() - date.getFullYear()) * 12 + (now.getMonth() - date.getMonth());
}

function humanAge(date: Date): string {
  const months = monthsSince(date);
  if (months < 1) return 'less than a month';
  if (months < 12) return `${months} month${months === 1 ? '' : 's'}`;
  const years = Math.floor(months / 12);
  return `${years} year${years === 1 ? '' : 's'}`;
}

function formatDate(date: Date): string {
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

async function tryRdapEndpoint(url: string, signal: AbortSignal): Promise<RdapData | null> {
  try {
    const res = await withTimeout(fetch(url, { signal }), 4000);
    if (!res.ok) return null;
    const data = await res.json();

    const registrationEvent = (data.events ?? []).find(
      (e: { eventAction: string }) => e.eventAction === 'registration'
    );
    if (!registrationEvent) return null;

    const registrarEntity = (data.entities ?? []).find(
      (e: { roles: string[] }) => e.roles?.includes('registrar')
    );
    const registrarName =
      registrarEntity?.vcardArray?.[1]?.find(
        (v: [string, ...unknown[]]) => v[0] === 'fn'
      )?.[3] ?? 'Unknown';

    return { registered: new Date(registrationEvent.eventDate), registrarName };
  } catch {
    return null;
  }
}

export async function checkDomainAge(hostname: string, signal: AbortSignal): Promise<CheckResult> {
  const domain = hostname.replace(/^www\./, '');

  const primary = await tryRdapEndpoint(`https://rdap.org/domain/${domain}`, signal);
  const rdap = primary ?? await tryRdapEndpoint(`https://rdap.verisign.com/com/v1/domain/${domain}`, signal);

  if (!rdap) {
    return {
      id: 'domainAge',
      label: 'Domain Age',
      summary: 'Domain info not available',
      score: 'warning',
      details: { Status: 'Not found' },
    };
  }

  const { registered, registrarName } = rdap;
  const months = monthsSince(registered);
  const age = humanAge(registered);
  const score: CheckResult['score'] = months < 6 ? 'warning' : 'trusted';
  const summary = months < 6 ? `Registered ${age} ago — new domain` : `Registered ${age} ago`;

  return {
    id: 'domainAge',
    label: 'Domain Age',
    summary,
    score,
    details: {
      Registered: formatDate(registered),
      Registrar: registrarName,
    },
  };
}
