import type { CheckResult } from '../../types/scan';

export async function checkSafeBrowsing(url: string, signal: AbortSignal): Promise<CheckResult> {
  const apiKey = import.meta.env.SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      id: 'safebrowsing',
      label: 'Google Safe Browsing',
      summary: 'Check not configured',
      score: 'unknown',
      details: { Status: 'Not configured' },
    };
  }

  try {
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        signal,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: { clientId: 'lunartrust', clientVersion: '1.0' },
          threatInfo: {
            threatTypes: [
              'MALWARE',
              'SOCIAL_ENGINEERING',
              'UNWANTED_SOFTWARE',
              'POTENTIALLY_HARMFUL_APPLICATION',
            ],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }],
          },
        }),
      }
    );

    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.error(`Safe Browsing API error ${res.status}:`, body);
      throw new Error(`API error: ${res.status}`);
    }

    const data = await res.json();
    const threats: { threatType: string }[] = data.matches ?? [];

    if (threats.length > 0) {
      const type = threats[0].threatType.replace(/_/g, ' ').toLowerCase();
      return {
        id: 'safebrowsing',
        label: 'Google Safe Browsing',
        summary: 'Threat detected — do not visit',
        score: 'danger',
        details: {
          Status: 'Threat found',
          'Threat type': type,
          'Threats found': String(threats.length),
        },
      };
    }

    return {
      id: 'safebrowsing',
      label: 'Google Safe Browsing',
      summary: 'No threats detected',
      score: 'trusted',
      details: {
        Status: 'Clean',
        'Threats found': '0',
      },
    };
  } catch {
    return {
      id: 'safebrowsing',
      label: 'Google Safe Browsing',
      summary: 'Check unavailable',
      score: 'unknown',
      details: { Status: 'Unavailable' },
    };
  }
}
