import type { CheckResult } from '../../types/scan';

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

export async function checkDomainAge(hostname: string, signal: AbortSignal): Promise<CheckResult> {
  const domain = hostname.replace(/^www\./, '');

  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, { signal });

    if (!res.ok) {
      return {
        id: 'domainAge',
        label: 'Domain Age',
        summary: 'Domain info not available',
        score: 'warning',
        details: { Status: 'Not found' },
      };
    }

    const data = await res.json();

    const registrationEvent = (data.events ?? []).find(
      (e: { eventAction: string }) => e.eventAction === 'registration'
    );

    if (!registrationEvent) {
      return {
        id: 'domainAge',
        label: 'Domain Age',
        summary: 'Registration date unknown',
        score: 'warning',
        details: { Status: 'Unknown' },
      };
    }

    const registered = new Date(registrationEvent.eventDate);
    const months = monthsSince(registered);
    const age = humanAge(registered);

    const registrarEntity = (data.entities ?? []).find(
      (e: { roles: string[] }) => e.roles?.includes('registrar')
    );
    const registrarName =
      registrarEntity?.vcardArray?.[1]?.find(
        (v: [string, ...unknown[]]) => v[0] === 'fn'
      )?.[3] ?? 'Unknown';

    const score: CheckResult['score'] = months < 6 ? 'warning' : 'trusted';
    const summary =
      months < 6 ? `Registered ${age} ago — new domain` : `Registered ${age} ago`;

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
  } catch {
    return {
      id: 'domainAge',
      label: 'Domain Age',
      summary: 'Check failed',
      score: 'warning',
      details: { Status: 'Unavailable' },
    };
  }
}
