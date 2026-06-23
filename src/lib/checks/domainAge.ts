import type { CheckResult } from '../../types/scan';

type RdapData = {
  registered: Date;
  registrarName: string;
  dateSource: 'registration' | 'last changed';
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

    const events: { eventAction: string; eventDate: string }[] = data.events ?? [];
    const registrationEvent = events.find((e) => e.eventAction === 'registration');
    const lastChangedEvent = events.find((e) => e.eventAction === 'last changed');
    const event = registrationEvent ?? lastChangedEvent;
    if (!event) return null;

    const registrarEntity = (data.entities ?? []).find(
      (e: { roles: string[] }) => e.roles?.includes('registrar')
    );
    const registrarName =
      registrarEntity?.vcardArray?.[1]?.find(
        (v: [string, ...unknown[]]) => v[0] === 'fn'
      )?.[3] ?? 'Unknown';

    return {
      registered: new Date(event.eventDate),
      registrarName,
      dateSource: registrationEvent ? 'registration' : 'last changed',
    };
  } catch {
    return null;
  }
}

// RDAP registry endpoints — fallback when rdap.org can't redirect
const RDAP_REGISTRY: Record<string, string> = {
  // Verisign gTLDs
  '.com':  'https://rdap.verisign.com/com/v1/domain/',
  '.net':  'https://rdap.verisign.com/com/v1/domain/',
  '.tv':   'https://rdap.nic.tv/domain/',
  // Google Registry gTLDs
  '.app':  'https://pubapi.registry.google/rdap/domain/',
  '.dev':  'https://pubapi.registry.google/rdap/domain/',
  '.page': 'https://pubapi.registry.google/rdap/domain/',
  // CentralNic
  '.fm':   'https://rdap.centralnic.com/fm/domain/',
  // Other gTLDs / widely-used ccTLDs
  '.me':   'https://rdap.nic.me/domain/',
  '.co':   'https://rdap.nic.co/domain/',
  // Europe
  '.de':   'https://rdap.denic.de/domain/',
  '.uk':   'https://rdap.nominet.uk/domain/',
  '.nl':   'https://rdap.sidn.nl/domain/',
  '.fr':   'https://rdap.nic.fr/domain/',
  '.eu':   'https://rdap.eu/domain/',
  '.it':   'https://rdap.nic.it/domain/',
  '.es':   'https://rdap.nic.es/domain/',
  '.pl':   'https://rdap.dns.pl/domain/',
  '.ch':   'https://rdap.nic.ch/domain/',
  '.at':   'https://rdap.nic.at/domain/',
  '.be':   'https://rdap.dns.be/domain/',
  '.se':   'https://rdap.iis.se/domain/',
  '.no':   'https://rdap.norid.no/domain/',
  '.dk':   'https://rdap.dk-hostmaster.dk/domain/',
  '.fi':   'https://rdap.fi/rdap/rdap/domain/',
  '.pt':   'https://rdap.dns.pt/domain/',
  '.cz':   'https://rdap.nic.cz/domain/',
  '.sk':   'https://rdap.sk-nic.sk/domain/',
  '.hu':   'https://rdap.nic.hu/domain/',
  '.ro':   'https://rdap.rotld.ro/domain/',
  // Americas
  '.br':   'https://rdap.registro.br/domain/',
  '.ca':   'https://rdap.ca.fury.ca/rdap/domain/',
  '.ar':   'https://rdap.nic.ar/domain/',
  // Asia-Pacific
  '.au':   'https://rdap.cctld.au/rdap/domain/',
  '.jp':   'https://rdap.nic.jprs/rdap/domain/',
  '.in':   'https://rdap.nixiregistry.in/rdap/domain/',
  '.sg':   'https://rdap.sgnic.sg/rdap/domain/',
  '.tw':   'https://ccrdap.twnic.tw/tw/domain/',
  '.id':   'https://rdap.pandi.id/rdap/domain/',
};

function getTld(domain: string): string {
  const parts = domain.split('.');
  return '.' + parts[parts.length - 1];
}

export async function checkDomainAge(hostname: string, signal: AbortSignal): Promise<CheckResult> {
  const domain = hostname.replace(/^www\./, '');
  const tld = getTld(domain);

  let rdap = await tryRdapEndpoint(`https://rdap.org/domain/${domain}`, signal);

  if (!rdap && RDAP_REGISTRY[tld]) {
    rdap = await tryRdapEndpoint(`${RDAP_REGISTRY[tld]}${domain}`, signal);
  }

  if (!rdap) {
    return {
      id: 'domainAge',
      label: 'Domain Age',
      summary: 'Domain info not available',
      score: 'unknown',
      details: { Status: 'Unavailable' },
    };
  }

  const { registered, registrarName, dateSource } = rdap;

  if (dateSource === 'last changed') {
    return {
      id: 'domainAge',
      label: 'Domain Age',
      summary: 'Registration date not disclosed',
      score: 'unknown',
      details: { Note: 'Registration date not disclosed by registry' },
    };
  }

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
