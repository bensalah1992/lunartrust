import tls from 'node:tls';
import type { CheckResult } from '../../types/scan';

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export function checkSSL(hostname: string, signal: AbortSignal): Promise<CheckResult> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, rejectUnauthorized: false, servername: hostname },
      () => {
        const cert = socket.getPeerCertificate();
        socket.end();

        if (!cert?.subject) {
          return resolve({
            id: 'ssl',
            label: 'SSL Certificate',
            summary: 'No valid certificate found',
            score: 'danger',
            details: { Status: 'No certificate' },
          });
        }

        const validTo = new Date(cert.valid_to);
        const daysRemaining = Math.floor(
          (validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24)
        );

        const rawOrg = cert.issuer?.O;
        const rawCN = cert.issuer?.CN;
        const org = Array.isArray(rawOrg) ? rawOrg[0] : rawOrg;
        const cn = Array.isArray(rawCN) ? rawCN[0] : rawCN;
        const issuer = org ?? cn ?? 'Unknown';
        const protocol = socket.getProtocol?.() ?? 'TLS';

        let score: CheckResult['score'];
        let summary: string;

        if (daysRemaining < 0) {
          score = 'danger';
          summary = 'Certificate has expired';
        } else if (daysRemaining < 14) {
          score = 'warning';
          summary = `Expires in ${daysRemaining} days`;
        } else {
          score = 'trusted';
          summary = `Valid · expires in ${daysRemaining} days`;
        }

        resolve({
          id: 'ssl',
          label: 'SSL Certificate',
          summary,
          score,
          details: {
            Issuer: issuer,
            Expires: formatDate(cert.valid_to),
            'Days remaining': String(daysRemaining),
            Protocol: protocol,
          },
        });
      }
    );

    socket.setTimeout(7000, () => {
      socket.destroy();
      resolve({
        id: 'ssl',
        label: 'SSL Certificate',
        summary: 'Check timed out',
        score: 'warning',
        details: { Status: 'Timeout' },
      });
    });

    socket.on('error', () =>
      resolve({
        id: 'ssl',
        label: 'SSL Certificate',
        summary: 'No SSL — connection not encrypted',
        score: 'danger',
        details: { Status: 'No HTTPS' },
      })
    );

    signal.addEventListener('abort', () => socket.destroy());
  });
}
