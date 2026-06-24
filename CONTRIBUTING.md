# Contributing to ProjectLunar

Thanks for taking the time to contribute. ProjectLunar is a URL trust scanner built for everyday users —>> simple, fast, and privacy-first.

## Getting Started

**Prerequisites:** Node.js ≥ 22.12, npm

```bash
# Fork on GitHub, then:
git clone https://github.com/<your-handle>/ProjectLunar.git
cd ProjectLunar
npm install
cp .env.example .env   # add your SAFE_BROWSING_API_KEY
npm run dev
```

The dev server starts at `http://localhost:4321`.

## Submitting a Pull Request

1. Create a branch off `main`: `git checkout -b feat/your-thing`
2. Make your changes >>> keep commits focused, one concern per commit.
3. Run `npm run build` to confirm no TypeScript or Astro errors before opening a PR.
4. Open a PR against `main` with a clear title using the commit convention below and a short description of what changed and why.

Commit convention: `feat:` · `fix:` · `style:` · `layout:` · `api:` · `docs:`

## Good First Contributions

These are concrete areas where help is welcome:

- **New URL check** — add a file to [src/lib/checks/](src/lib/checks/) following the pattern of the existing checks (`domainAge.ts`, `ssl.ts`, etc.) and wire it into [src/pages/api/scan.ts](src/pages/api/scan.ts). All checks run in parallel via `Promise.allSettled()` with an 8-second timeout.
- **Scoring rules** — improve the risk logic in [src/lib/scoring.ts](src/lib/scoring.ts). Rules must be transparent and explainable to non-technical users.
- **Accessibility** — audit and improve keyboard nav, focus styles, and ARIA labels in the Astro components under [src/components/](src/components/).
- **CSS polish** — all styles use CSS variables (see [src/styles/](src/styles/)). No Tailwind, no external animation libraries.
- **Copy / i18n** — plain-language improvements to result messages, the FAQ, or Privacy/Impressum pages.

## Code Style

- **TypeScript** for all logic files — strict mode, no `any`.
- **Astro components** (`.astro`) for all UI.
- **CSS variables only** —> never hardcode colors. Signal colors (green/yellow/red) are reserved for scan results.
- **PascalCase** for component files, **camelCase** for variables and functions.
- No external UI libraries or JS animation packages.
- Keep components focused >>> prefer smaller, single-purpose files.
- Comments only when the _why_ is non-obvious.

## Security & Privacy

ProjectLunar's core promise is that no URL is stored or logged. Keep that promise in every change:

- Never log, store, or forward scanned URLs.
- API keys go in Netlify environment variables only — never in code or committed files.
- For new API integrations, add a key name to `.env.example` (with a placeholder value) and document the service in the PR description.

## Reporting Issues

Open an issue on GitHub with:

- The URL pattern that triggered the problem (you can anonymize it).
- What verdict you got vs. what you expected.
- Browser and OS if it's a display/UX bug.

For security vulnerabilities, please email [ab.bensalah@protonmail.com](mailto:ab.bensalah@pm.me) instead of opening a public issue.
