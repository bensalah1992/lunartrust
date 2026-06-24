# LunarTrust

A free, open source URL trust scanner for everyday users. Paste any URL and get a clear green / yellow / red verdict in seconds.

## I'm still learning. If you're an experienced developer and something could be done better, I'd genuinely appreciate the feedback. Open an issue, submit a PR, or reach out directly. ## See [CONTRIBUTING.md](CONTRIBUTING.md)

![LunarTrust Screenshot](public/screenshot.png)

**Live demo:** [lunartrust.netlify.app](https://lunartrust.netlify.app)

---

## What it checks

Five checks run in parallel on every scan:

| Check                | What it looks for                                                                                  |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| SSL Certificate      | Encrypted connection, validity, expiry                                                             |
| Google Safe Browsing | Known malware and phishing URLs                                                                    |
| Domain Age           | Domains under 6 months are flagged                                                                 |
| Wayback Machine      | No archive history is a warning signal                                                             |
| URL Analysis         | Local heuristic — phishing patterns, brand impersonation, suspicious TLDs, typosquatting, and more |

## Privacy

Privacy is the core principle behind LunarTrust. I do not store, log, or track any URLs you scan, not in a database, not in any log file. The URL Analysis check is fully local and never contacts an external service.

The one honest exception: the Google Safe Browsing check sends the URL to Google's API. I include it because it is one of the most effective threat databases available, but I want to be upfront about the trade-off. If you consider a URL sensitive, the other four checks still run independently. The full details are in the [Privacy Policy](/privacy).

## Tech stack

- [Astro](https://astro.build) — SSR framework with Netlify adapter
- TypeScript — strict mode throughout
- Netlify — hosting and serverless functions
- Plain CSS with CSS variables — no Tailwind, no UI libraries

## Run locally

```bash
git clone https://github.com/bensalah1992/ProjectLunar.git
cd lunartrust
npm install
```

Create a `.env` file in the project root

Start the dev server:

```bash
npm run dev
```

Open [http://localhost:4321](http://localhost:4321).

## Get a Google Safe Browsing API key

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a project and enable the **Safe Browsing API**
3. Go to **APIs & Services → Credentials** and create an API key
4. Add it to your `.env` file as shown above

The app works without the key. That check will return unknown and not affect the score.

## Contributing

## A note from the developer

Contributions are welcome. A good starting point is `src/lib/checks/heuristics.ts` —> adding brand entries, suspicious TLDs, or phishing path keywords requires no deep knowledge of the codebase. Please open an issue before submitting a large pull request.

## License

MIT — see [LICENSE](LICENSE).

The MIT license applies to the source code only. The name LunarTrust, the logo, and all written content are not covered by this license.
