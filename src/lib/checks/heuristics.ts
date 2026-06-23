import type { CheckResult } from '../../types/scan';

// High-abuse TLDs
const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',
  'top', 'xyz', 'icu', 'cyou', 'sbs',
  'buzz', 'click', 'download', 'loan', 'win',
  'racing', 'date', 'review', 'trade', 'stream',
  'cricket', 'science', 'work', 'party', 'bid',
  'webcam', 'faith', 'men', 'accountant', 'gdn',
  'monster', 'quest', 'cfd',
]);

// Executables and scripts — run code when opened
const EXECUTABLE_EXTENSIONS = new Set([
  'exe', 'msi', 'bat', 'cmd', 'vbs', 'vbe', 'jse', 'wsf', 'wsh',
  'ps1', 'ps2', 'psc1', 'psc2', 'scr', 'pif', 'reg',
  'dmg', 'pkg', 'mpkg',
  'apk', 'ipa', 'xapk',
  'jar', 'jnlp',
  'iso', 'img',
  'deb', 'rpm', 'run', 'sh',
]);

// Archives commonly used to deliver malware
const ARCHIVE_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'tgz', 'tbz2',
  'tar', 'cab', 'arc', 'ace', 'z', 'lz', 'lzma', 'zipx',
]);

// URL shorteners — real destination is hidden
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl',
  'buff.ly', 'dlvr.it', 'ift.tt', 'tiny.cc', 'is.gd',
  'v.gd', 'rb.gy', 'cutt.ly', 'tr.im', 'shorturl.at',
  'snip.ly', 'mcaf.ee', 'j.mp', 'tiny.one', 'qr.ae',
  't2m.io', 'bl.ink', 'rebrand.ly', 'go2l.ink', 's.id',
  'clck.ru', 'tny.im', 'han.gl', 'adf.ly', 'urlzs.com',
  'shorte.st', 'bc.vc', 'links.gg', 'ouo.io',
]);

// Free hosting platforms — checked for brand-in-subdomain only
const FREE_HOSTING = new Set([
  '000webhostapp.com', 'weebly.com', 'wixsite.com',
  'jimdo.com', 'firebaseapp.com', 'web.app',
]);

// Preview / hobby hosting platforms
const DEVELOPER_PLATFORMS = new Set([
  'vercel.app', 'netlify.app', 'pages.dev', 'github.io',
  'gitlab.io', 'glitch.me', 'replit.com', 'repl.co',
  'render.com', 'railway.app', 'fly.dev', 'surge.sh',
  'tiiny.site', 'netlify.com',
]);

// Query parameters that trigger file downloads
const DOWNLOAD_PARAMS = new Set([
  'download', 'dl', 'install', 'setup', 'get',
]);

// Subdomain keywords associated with malware distribution
const MALWARE_SUBDOMAIN_KEYWORDS = [
  'download', 'installer', 'install', 'setup', 'crack',
  'keygen', 'warez', 'nulled', 'cheat', 'hack',
];

// Path keywords common in phishing flows (weak signal)
const PHISHING_PATH_KEYWORDS = [
  'verify', 'verification', 'validate', 'confirm', 'secure',
  'login', 'signin', 'sign-in', 'log-in', 'account', 'password',
  'credential', 'recover', 'reset', 'unlock', 'suspended',
  'wallet', 'banking', 'invoice', 'billing', 'payment-update',
];

// Most-impersonated brands in phishing
const BRANDS: string[] = [
  // ── Global tech ────────────────────────────────────────────────
  'google', 'apple', 'microsoft', 'amazon', 'meta', 'facebook',
  'instagram', 'twitter', 'tiktok', 'youtube', 'netflix', 'linkedin',
  'github', 'adobe', 'dropbox', 'salesforce', 'slack', 'zoom',
  // ── Payment & fintech ──────────────────────────────────────────
  'paypal', 'stripe', 'square', 'klarna', 'revolut', 'wise',
  'venmo', 'cashapp', 'skrill', 'neteller', 'westernunion',
  // ── E-commerce ─────────────────────────────────────────────────
  'ebay', 'etsy', 'shopify', 'aliexpress', 'alibaba', 'zalando', 'asos', 'ikea',
  // ── Gaming ─────────────────────────────────────────────────────
  'steam', 'epicgames', 'blizzard', 'roblox', 'riotgames',
  'rockstar', 'playstation', 'xbox', 'nintendo', 'ubisoft',
  // ── Streaming ──────────────────────────────────────────────────
  'spotify', 'disney', 'hbo', 'twitch', 'soundcloud', 'deezer', 'primevideo',
  // ── Social / messaging ─────────────────────────────────────────
  'reddit', 'pinterest', 'snapchat', 'discord', 'telegram',
  'whatsapp', 'signal', 'viber',
  // ── Crypto ─────────────────────────────────────────────────────
  'binance', 'coinbase', 'kraken', 'metamask', 'ledger',
  'bitfinex', 'okx', 'bybit', 'kucoin', 'opensea', 'uniswap', 'phantom',
  // ── Logistics ──────────────────────────────────────────────────
  'dhl', 'fedex', 'ups', 'usps', 'royalmail', 'laposte', 'correos',
  'postnl', 'postnord', 'dpd', 'gls', 'evri', 'bpost',
  'posteitaliane', 'deutschepost', 'swisspost', 'ctt',
  // ── Travel ─────────────────────────────────────────────────────
  'airbnb', 'booking', 'expedia', 'tripadvisor', 'ryanair',
  'lufthansa', 'britishairways', 'airfrance', 'easyjet', 'eurowings',
  // ── Banking — North America ────────────────────────────────────
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'usbank', 'capitalone',
  // ── Banking — UK ───────────────────────────────────────────────
  'barclays', 'lloyds', 'natwest', 'hsbc',
  // ── Banking — Germany ──────────────────────────────────────────
  'sparkasse', 'commerzbank', 'volksbank', 'postbank', 'dkb', 'n26', 'ingdiba',
  // ── Banking — France ───────────────────────────────────────────
  'bnpparibas', 'societegenerale', 'creditagricole', 'banquepostale',
  // ── Banking — Spain / Italy / Netherlands / Belgium ────────────
  'santander', 'bbva', 'caixabank', 'unicredit', 'intesasanpaolo',
  'rabobank', 'abnamro', 'kbc', 'belfius', 'ing',
  // ── Telecom ────────────────────────────────────────────────────
  'telekom', 'vodafone', 'orange', 'tmobile', 'att', 'verizon',
  'swisscom', 'proximus', 'telefonica',
  // ── Security vendors ───────────────────────────────────────────
  'norton', 'mcafee', 'avast', 'kaspersky', 'bitdefender', 'malwarebytes',
];

const BRAND_DOMAINS: Record<string, string[]> = {
  google:          ['google.com', 'googleapis.com', 'googleusercontent.com'],
  apple:           ['apple.com', 'icloud.com', 'me.com'],
  microsoft:       ['microsoft.com', 'live.com', 'hotmail.com', 'outlook.com', 'office.com', 'azure.com', 'microsoftonline.com', 'office365.com'],
  amazon:          ['amazon.com', 'amazon.de', 'amazon.co.uk', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.nl', 'amazon.pl', 'amazonaws.com'],
  meta:            ['meta.com', 'facebook.com', 'fb.com', 'instagram.com', 'whatsapp.com', 'fbcdn.net'],
  facebook:        ['facebook.com', 'fb.com', 'fbcdn.net'],
  instagram:       ['instagram.com'],
  twitter:         ['twitter.com', 'x.com', 't.co'],
  tiktok:          ['tiktok.com', 'tiktokcdn.com'],
  youtube:         ['youtube.com', 'youtu.be', 'ytimg.com'],
  netflix:         ['netflix.com'],
  linkedin:        ['linkedin.com'],
  github:          ['github.com', 'github.io', 'githubusercontent.com', 'githubassets.com'],
  adobe:           ['adobe.com'],
  dropbox:         ['dropbox.com', 'dropboxusercontent.com'],
  slack:           ['slack.com'],
  zoom:            ['zoom.us', 'zoom.com'],
  paypal:          ['paypal.com', 'paypal.de', 'paypal.co.uk', 'paypal.fr', 'paypal.me', 'paypalobjects.com'],
  stripe:          ['stripe.com'],
  klarna:          ['klarna.com'],
  revolut:         ['revolut.com'],
  wise:            ['wise.com', 'transferwise.com'],
  cashapp:         ['cash.app', 'cashapp.com'],
  ebay:            ['ebay.com', 'ebay.de', 'ebay.co.uk', 'ebay.fr', 'ebay.it', 'ebay.es'],
  etsy:            ['etsy.com'],
  shopify:         ['shopify.com', 'myshopify.com'],
  aliexpress:      ['aliexpress.com'],
  alibaba:         ['alibaba.com', 'alibabacloud.com'],
  steam:           ['steampowered.com', 'steamcommunity.com'],
  epicgames:       ['epicgames.com'],
  blizzard:        ['blizzard.com', 'battle.net'],
  roblox:          ['roblox.com'],
  riotgames:       ['riotgames.com', 'leagueoflegends.com', 'valorant.com'],
  rockstar:        ['rockstargames.com'],
  playstation:     ['playstation.com', 'playstation.net'],
  xbox:            ['xbox.com', 'xboxlive.com'],
  nintendo:        ['nintendo.com'],
  spotify:         ['spotify.com'],
  disney:          ['disney.com', 'disneyplus.com'],
  twitch:          ['twitch.tv'],
  discord:         ['discord.com', 'discord.gg', 'discordapp.com'],
  telegram:        ['telegram.org', 't.me'],
  whatsapp:        ['whatsapp.com', 'wa.me'],
  signal:          ['signal.org'],
  reddit:          ['reddit.com', 'redd.it', 'redditmedia.com'],
  snapchat:        ['snapchat.com', 'snap.com'],
  binance:         ['binance.com'],
  coinbase:        ['coinbase.com'],
  kraken:          ['kraken.com'],
  metamask:        ['metamask.io'],
  ledger:          ['ledger.com'],
  dhl:             ['dhl.com', 'dhl.de', 'dhl.co.uk', 'dhl.fr', 'dhl.it', 'dhl.es'],
  fedex:           ['fedex.com'],
  ups:             ['ups.com'],
  usps:            ['usps.com'],
  royalmail:       ['royalmail.com'],
  laposte:         ['laposte.fr', 'colissimo.fr'],
  postnl:          ['postnl.nl', 'postnl.com'],
  dpd:             ['dpd.com', 'dpd.de', 'dpd.co.uk', 'dpd.fr'],
  evri:            ['evri.com'],
  bpost:           ['bpost.be'],
  posteitaliane:   ['poste.it'],
  deutschepost:    ['deutschepost.de'],
  swisspost:       ['post.ch'],
  airbnb:          ['airbnb.com'],
  booking:         ['booking.com'],
  expedia:         ['expedia.com'],
  ryanair:         ['ryanair.com'],
  lufthansa:       ['lufthansa.com'],
  britishairways:  ['britishairways.com', 'ba.com'],
  airfrance:       ['airfrance.com', 'airfrance.fr'],
  chase:           ['chase.com'],
  wellsfargo:      ['wellsfargo.com'],
  bankofamerica:   ['bankofamerica.com'],
  citibank:        ['citibank.com', 'citi.com'],
  capitalone:      ['capitalone.com'],
  hsbc:            ['hsbc.com', 'hsbc.co.uk'],
  barclays:        ['barclays.co.uk', 'barclays.com'],
  lloyds:          ['lloydsbank.com'],
  natwest:         ['natwest.com'],
  santander:       ['santander.com', 'santander.co.uk', 'santander.de', 'santander.es'],
  bbva:            ['bbva.com', 'bbva.es'],
  caixabank:       ['caixabank.com', 'caixabank.es', 'lacaixa.es'],
  bnpparibas:      ['bnpparibas.com', 'bnpparibas.fr'],
  societegenerale: ['societegenerale.fr', 'societegenerale.com'],
  creditagricole:  ['credit-agricole.fr', 'ca-online.fr'],
  unicredit:       ['unicredit.eu', 'unicredit.de', 'unicredit.it'],
  intesasanpaolo:  ['intesasanpaolo.com'],
  rabobank:        ['rabobank.nl', 'rabobank.com'],
  abnamro:         ['abnamro.nl', 'abnamro.com'],
  kbc:             ['kbc.be'],
  belfius:         ['belfius.be'],
  sparkasse:       ['sparkasse.de'],
  commerzbank:     ['commerzbank.de'],
  volksbank:       ['volksbank.de'],
  postbank:        ['postbank.de'],
  dkb:             ['dkb.de'],
  n26:             ['n26.com'],
  ingdiba:         ['ing-diba.de', 'ing.de'],
  ing:             ['ing.nl', 'ing.be', 'ing.de'],
  telekom:         ['telekom.de', 't-online.de', 'telekom.com'],
  vodafone:        ['vodafone.com', 'vodafone.de', 'vodafone.co.uk'],
  orange:          ['orange.com', 'orange.fr'],
  att:             ['att.com'],
  verizon:         ['verizon.com'],
  swisscom:        ['swisscom.ch'],
  proximus:        ['proximus.be'],
  telefonica:      ['telefonica.com'],
  norton:          ['norton.com', 'nortonlifelock.com', 'gen.com'],
  mcafee:          ['mcafee.com'],
  avast:           ['avast.com'],
  kaspersky:       ['kaspersky.com'],
  bitdefender:     ['bitdefender.com'],
  malwarebytes:    ['malwarebytes.com'],
};

const COMMON_GTLDS = new Set(['com', 'net', 'org', 'co', 'io', 'app', 'dev', 'gov', 'edu', 'int']);

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

function normalize(s: string): string {
  return s
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/8/g, 'b')
    .replace(/vv/g, 'w').replace(/rn/g, 'm').replace(/-/g, '');
}

function isLegitimate(hostname: string, brand: string): boolean {
  const allowed = BRAND_DOMAINS[brand] ?? [];
  return allowed.some((d) => hostname === d || hostname.endsWith('.' + d));
}

interface Flag {
  level: 'danger' | 'warning';
  label: string;
  detail: string;
}

export async function checkHeuristics(rawUrl: string): Promise<CheckResult> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      id: 'heuristics',
      label: 'URL Analysis',
      summary: 'Could not parse URL',
      score: 'unknown',
      details: { Status: 'Invalid URL' },
    };
  }

  const scheme   = parsed.protocol.replace(':', '').toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search   = parsed.search;
  const qp       = new URLSearchParams(search);

  const flags: Flag[] = [];
  let weakSignals = 0;

  // Composite ccTLD support (.co.uk, .com.au) — steps back one extra level for SLD extraction.
  const tldMatch = hostname.match(/\.([a-z]+)$/);
  const tld = tldMatch?.[1] ?? '';
  const isCcTld = tld.length === 2;
  const hostPartsRaw = hostname.replace(/^www\./, '').split('.');
  const COMPOSITE_SECOND_LEVELS = new Set(['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'or', 'ne']);
  const penultimate = hostPartsRaw.length >= 2 ? hostPartsRaw[hostPartsRaw.length - 2] : '';
  const hasCompositeTld = isCcTld && COMPOSITE_SECOND_LEVELS.has(penultimate) && hostPartsRaw.length >= 3;
  const sld = hasCompositeTld
    ? hostPartsRaw[hostPartsRaw.length - 3]
    : (hostPartsRaw.length >= 2 ? hostPartsRaw[hostPartsRaw.length - 2] : hostPartsRaw[0]);
  const normSld = normalize(sld);

  // ── 1. Dangerous URI scheme ──────────────────────────────────
  if (['javascript', 'data', 'vbscript'].includes(scheme)) {
    flags.push({
      level: 'danger',
      label: 'Dangerous URI scheme',
      detail: `"${scheme}:" can execute code directly in the browser without loading a real page`,
    });
  }

  // ── 2. IP address as hostname ────────────────────────────────
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')) {
    flags.push({
      level: 'danger',
      label: 'IP address as host',
      detail: 'Legitimate websites use domain names, not raw IP addresses',
    });
  }

  // ── 3. @ in URL — hides the real navigation target ──────────
  const afterScheme = rawUrl.slice(rawUrl.indexOf('://') + 3);
  const atIndex = afterScheme.indexOf('@');
  if (atIndex !== -1 && atIndex < (afterScheme.indexOf('/') === -1 ? afterScheme.length : afterScheme.indexOf('/'))) {
    flags.push({
      level: 'danger',
      label: '@ in URL',
      detail: 'The browser navigates to the part after @ — everything before it is a decoy',
    });
  }

  // ── 4. File extension checks ────────────────────────────────
  const extMatch = pathname.match(/\.([a-z0-9]{1,5})(?:[?#]|$)/i);
  const ext = extMatch?.[1]?.toLowerCase() ?? '';
  if (ext && EXECUTABLE_EXTENSIONS.has(ext)) {
    flags.push({
      level: 'warning',
      label: `Executable file link (.${ext})`,
      detail: 'URL leads directly to an executable or installer — only download from sources you fully trust',
    });
  } else if (ext && ARCHIVE_EXTENSIONS.has(ext)) {
    flags.push({
      level: 'warning',
      label: `Archive file download (.${ext})`,
      detail: 'URL delivers a compressed archive — archives frequently contain executable files or malware. Verify the publisher before extracting.',
    });
  }

  // ── 5. Download / install trigger in query parameters ────────
  const triggeredDownloadParam = [...qp.keys()].find((k) => DOWNLOAD_PARAMS.has(k.toLowerCase()));
  if (triggeredDownloadParam) {
    flags.push({
      level: 'warning',
      label: 'Download trigger parameter',
      detail: `The "?${triggeredDownloadParam}=" parameter is commonly used to initiate a file download automatically`,
    });
  }

  // ── 6. Punycode / IDN homograph ─────────────────────────────
  if (hostname.includes('xn--')) {
    flags.push({
      level: 'warning',
      label: 'Internationalized domain (IDN)',
      detail: 'Uses encoded characters that may visually mimic a well-known site (e.g. ɑpple.com)',
    });
  }

  // ── 7. URL shortener ────────────────────────────────────────
  if (URL_SHORTENERS.has(hostname)) {
    flags.push({
      level: 'warning',
      label: 'URL shortener',
      detail: 'The real destination is hidden behind a redirect — impossible to verify without clicking',
    });
  }

  // ── 7b. Security keyword in SLD (e.g. https-paypal.com) ────
  // Checks SLD hyphen-parts only — avoids false positives for secure.paypal.com.
  {
    const segments = sld.split('-');
    if (segments.some((s) => ['http', 'https', 'ssl', 'tls', 'secure'].includes(s))) {
      flags.push({
        level: 'warning',
        label: 'Security keyword in domain name',
        detail: 'Legitimate sites never put "https", "ssl", or "secure" in their domain name — this is a known phishing pattern',
      });
    }
  }

  // ── 8. Suspicious TLD ───────────────────────────────────────
  const isSuspiciousTld = tld !== '' && SUSPICIOUS_TLDS.has(tld);
  if (isSuspiciousTld) {
    flags.push({
      level: 'warning',
      label: `High-abuse TLD (.${tld})`,
      detail: 'This domain extension has a disproportionately high rate of phishing and malware',
    });
  }

  // ── 9. Developer / preview platform subdomain ───────────────
  let onDeveloperPlatform = false;
  for (const platform of DEVELOPER_PLATFORMS) {
    if (hostname.endsWith('.' + platform)) {
      onDeveloperPlatform = true;
      flags.push({
        level: 'warning',
        label: 'Developer platform subdomain',
        detail: `Hosted on ${platform} — production sites use custom domains; this could be a preview, a personal project, or a phishing page`,
      });
      break;
    }
  }

  // ── 10. Suspicious keyword in subdomain ─────────────────────
  const subdomainParts = hostname.replace(/^www\./, '').split('.').slice(0, -2);
  const subdomainStr = subdomainParts.join('.');
  const hitKeyword = MALWARE_SUBDOMAIN_KEYWORDS.find((kw) => subdomainStr.includes(kw));
  if (hitKeyword && subdomainStr.length > 0) {
    flags.push({
      level: 'warning',
      label: 'Suspicious subdomain keyword',
      detail: `Subdomain contains "${hitKeyword}" — a keyword frequently found in malware distribution URLs`,
    });
  }

  // ── 11. Brand impersonation checks ──────────────────────────
  let brandFlagged = false;

  for (const brand of BRANDS) {
    if (isLegitimate(hostname, brand)) continue;

    // 11a. Brand domain as fake subdomain — e.g. paypal.com.attacker.xyz
    for (const d of (BRAND_DOMAINS[brand] ?? [])) {
      if (hostname.includes(d + '.')) {
        flags.push({
          level: 'danger',
          label: `Impersonates ${brand}`,
          detail: `"${d}" appears as a fake subdomain to make the URL look legitimate`,
        });
        brandFlagged = true;
        break;
      }
    }
    if (brandFlagged) break;

    // 11b. Exact SLD match — risk depends on TLD
    const isExact = sld === brand;
    const isSubstitution = !isExact && normSld === brand;

    if (isExact || isSubstitution) {
      if (isSuspiciousTld) {
        flags.push({
          level: 'danger',
          label: `Impersonates ${brand}`,
          detail: `"${brand}" on a high-abuse TLD (.${tld}) — strong phishing indicator`,
        });
      } else if (isSubstitution) {
        flags.push({
          level: 'danger',
          label: `Impersonates ${brand}`,
          detail: `"${sld}" uses character substitution to visually mimic "${brand}"`,
        });
      } else if (!isCcTld && !COMMON_GTLDS.has(tld)) {
        flags.push({
          level: 'warning',
          label: `Possible ${brand} impersonation`,
          detail: `Domain matches "${brand}" exactly but uses an unusual TLD (.${tld})`,
        });
      }
      brandFlagged = true;
      break;
    }

    // 11c. One character off (paypa1, gooogle, amaz0n)
    if (brand.length > 4 && levenshtein(normSld, brand) === 1) {
      flags.push({
        level: 'danger',
        label: `Typosquat of ${brand}`,
        detail: `"${sld}" differs from "${brand}" by only one character`,
      });
      brandFlagged = true;
      break;
    }
  }

  // 11d. Brand keyword + hyphen in SLD (paypal-secure.com, amazon-login.de)
  if (!brandFlagged) {
    for (const brand of BRANDS) {
      if (brand.length < 5) continue;
      if (isLegitimate(hostname, brand)) continue;
      if (sld.includes(`${brand}-`) || sld.includes(`-${brand}`)) {
        flags.push({
          level: 'warning',
          label: 'Brand name with hyphens',
          detail: `"${brand}" combined with hyphens in the domain — a common phishing construction`,
        });
        brandFlagged = true;
        break;
      }
    }
  }

  // 11e. Brand in subdomain of free hosting platform (paypal.weebly.com)
  if (!brandFlagged) {
    for (const freeHost of FREE_HOSTING) {
      if (hostname.endsWith('.' + freeHost)) {
        const sub = hostname.slice(0, hostname.length - freeHost.length - 1);
        for (const brand of BRANDS) {
          if (brand.length >= 5 && sub.includes(brand)) {
            flags.push({
              level: 'warning',
              label: 'Brand on free hosting platform',
              detail: `"${brand}" found on "${freeHost}" — free hosting is frequently abused for phishing`,
            });
            brandFlagged = true;
            break;
          }
        }
        if (brandFlagged) break;
      }
    }
  }

  // ── 12. Open redirect parameter ─────────────────────────────
  const REDIRECT_PARAMS = new Set([
    'url', 'redirect', 'next', 'goto', 'return', 'returnurl',
    'continue', 'dest', 'destination', 'rurl', 'ref', 'out', 'target',
  ]);
  if ([...qp.keys()].some((k) => REDIRECT_PARAMS.has(k.toLowerCase()))) {
    flags.push({
      level: 'warning',
      label: 'Open redirect parameter',
      detail: 'URL contains a redirect parameter that may silently forward you to a different site',
    });
  }

  // ── 13. Excessive subdomain depth ───────────────────────────
  const subdomainDepth = hostname.split('.').length - 2;
  if (subdomainDepth > 3) {
    flags.push({
      level: 'warning',
      label: 'Excessive subdomain depth',
      detail: `${subdomainDepth} subdomain levels — legitimate sites rarely exceed 2`,
    });
  }

  // ── 14. Non-standard port ────────────────────────────────────
  if (parsed.port && !['80', '443'].includes(parsed.port)) {
    flags.push({
      level: 'warning',
      label: `Non-standard port (${parsed.port})`,
      detail: 'Public websites do not serve pages on non-standard ports',
    });
  }

  // ── Weak signals (each adds 1 point; shown only if 2+ accumulate) ──
  if (PHISHING_PATH_KEYWORDS.some((kw) => pathname.includes(kw))) weakSignals++;
  // Literal path segment — distinct from the ?download= param check above
  if (pathname.split('/').some((seg) => seg === 'download' || seg === 'dl')) weakSignals++;
  if (sld.length > 30) weakSignals++;
  if ((sld.match(/\d/g) ?? []).length >= 3) weakSignals++;
  if (/--/.test(sld)) weakSignals++;
  if (sld.length > 6 && !/[aeiou]/.test(sld)) weakSignals++;
  if (onDeveloperPlatform && triggeredDownloadParam) weakSignals++;

  if (weakSignals >= 2) {
    flags.push({
      level: 'warning',
      label: 'Multiple structural anomalies',
      detail: `${weakSignals} unusual URL characteristics found — may indicate an obfuscated or auto-generated domain`,
    });
  }

  // ── Build result ─────────────────────────────────────────────
  const dangerFlags  = flags.filter((f) => f.level === 'danger');
  const warningFlags = flags.filter((f) => f.level === 'warning');

  const details: Record<string, string> = {};
  if (flags.length === 0) {
    details['Status']     = 'No suspicious patterns detected';
    details['Checks run'] = '20';
  } else {
    details['Issues found'] = String(flags.length);
    for (const f of flags) {
      details[f.label] = f.detail;
    }
  }

  if (dangerFlags.length > 0) {
    return {
      id: 'heuristics',
      label: 'URL Analysis',
      summary: dangerFlags[0].label,
      score: 'danger',
      details,
    };
  }

  if (warningFlags.length > 0) {
    const summary =
      warningFlags.length === 1
        ? warningFlags[0].label
        : `${warningFlags.length} suspicious patterns detected`;
    return {
      id: 'heuristics',
      label: 'URL Analysis',
      summary,
      score: 'warning',
      details,
    };
  }

  return {
    id: 'heuristics',
    label: 'URL Analysis',
    summary: 'No suspicious patterns detected',
    score: 'trusted',
    details,
  };
}
