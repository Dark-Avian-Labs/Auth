# Changelog

Notable work on `main` is summarized **by merged pull request**, one line each, conventional-commit style.

## SemVer (baseline **1.0.0**)

Existing package/release numbers are ignored for this backfill.

Rules:

- `feat` → **minor** (patch resets to 0)
- `fix`, `perf`, `revert` → **patch**
- `chore` → **patch** (project rule)
- `ci` alone → **patch** (same as chore for this simulation)
- **BREAKING CHANGE** / `!` → **major** (not inferred from branch names here)

## Early `main` (before PR #3)

- `chore`: initial Auth service, admin UI, login branding, static rate limits, deploy/ecosystem churn (no PR merge commits yet)

## Pull requests (oldest → newest)

- **v1.0.1** `fix` [#3](https://github.com/Dark-Avian-Labs/Auth/pull/3): derive `COOKIE_DOMAIN` from `AUTH_PUBLIC_BASE_URL`
- **v1.0.2** `fix` [#4](https://github.com/Dark-Avian-Labs/Auth/pull/4): tighten deploy SSH; add `/health` + readiness; harden prod cookies
- **v1.0.3** `ci` [#5](https://github.com/Dark-Avian-Labs/Auth/pull/5): migrate workflows to Blacksmith runners
- **v1.0.4** `ci` [#6](https://github.com/Dark-Avian-Labs/Auth/pull/6): use 2vCPU Blacksmith runners for format/lint
- **v1.1.0** `feat` [#7](https://github.com/Dark-Avian-Labs/Auth/pull/7): env + domain cutover; cookie/session tweaks for new URL
- **v1.2.0** `feat` [#8](https://github.com/Dark-Avian-Labs/Auth/pull/8): admin password changes; update cross-app navigation URLs
- **v1.3.0** `feat` [#9](https://github.com/Dark-Avian-Labs/Auth/pull/9): rebuild on shared AppBase scaffold; simplify auth/domain logic
- **v1.3.1** `fix` [#10](https://github.com/Dark-Avian-Labs/Auth/pull/10): repair env + deploy wiring after scaffold
- **v1.3.2** `fix` [#11](https://github.com/Dark-Avian-Labs/Auth/pull/11): more auth + env regressions post-migration
- **v1.3.3** `fix` [#12](https://github.com/Dark-Avian-Labs/Auth/pull/12): profile icons + other missed migration UI
- **v1.3.4** `fix` [#13](https://github.com/Dark-Avian-Labs/Auth/pull/13): brand lockup / layout CSS cleanup
- **v1.3.5** `fix` [#14](https://github.com/Dark-Avian-Labs/Auth/pull/14): additional migration fixes
- **v1.3.6** `fix` [#15](https://github.com/Dark-Avian-Labs/Auth/pull/15): more migration cleanup
- **v1.3.7** `chore` [#16](https://github.com/Dark-Avian-Labs/Auth/pull/16): unify `.gitignore`
- **v1.3.8** `chore` [#17](https://github.com/Dark-Avian-Labs/Auth/pull/17): introduce `development` integration branch workflow
- **v1.3.9** `chore` [#18](https://github.com/Dark-Avian-Labs/Auth/pull/18): expand CI (typecheck/lint/test) + formatting/test fixes
- **v1.3.10** `chore` [#19](https://github.com/Dark-Avian-Labs/Auth/pull/19): bump `@types/node` (Dependabot dev group)
- **v1.3.11** `chore` [#20](https://github.com/Dark-Avian-Labs/Auth/pull/20): remove redundant comment in env bootstrap
- **v1.3.12** `chore` [#21](https://github.com/Dark-Avian-Labs/Auth/pull/21): drive SSH setup from CI env vars
- **v1.3.13** `chore` [#22](https://github.com/Dark-Avian-Labs/Auth/pull/22): CodeRabbit audit follow-ups (security/quality)
- **v1.3.14** `chore` [#24](https://github.com/Dark-Avian-Labs/Auth/pull/24): add validation npm script; small `LoginPage` comment tweak
- **v1.3.15** `fix` [#25](https://github.com/Dark-Avian-Labs/Auth/pull/25): Vite env handling / typings
- **v1.3.16** `fix` [#26](https://github.com/Dark-Avian-Labs/Auth/pull/26): bump/fix `express-rate-limit` integration
- **v1.4.0** `feat` [#27](https://github.com/Dark-Avian-Labs/Auth/pull/27): client auth UX for rate limits + forbidden access
- **v1.5.0** `feat` [#28](https://github.com/Dark-Avian-Labs/Auth/pull/28): configurable auth API rate limits via env vars
- **v1.5.1** `fix` [#30](https://github.com/Dark-Avian-Labs/Auth/pull/30): refine rate-limit response handling (refactor/hardening)
- **v1.5.2** `chore` [#31](https://github.com/Dark-Avian-Labs/Auth/pull/31): deploy workflows respect SSH port configuration
- **v1.6.0** `feat` [#32](https://github.com/Dark-Avian-Labs/Auth/pull/32): adopt `dotenvx`; encrypted env in deploy + docs
- **v1.6.1** `chore` [#35](https://github.com/Dark-Avian-Labs/Auth/pull/35): dependency bumps (`package-lock` era)
- **v1.6.2** `fix` [#36](https://github.com/Dark-Avian-Labs/Auth/pull/36): env file discovery, `.env.keys` deploy flow, dotenvx rollout fixes
- **v1.7.0** `feat` [#37](https://github.com/Dark-Avian-Labs/Auth/pull/37): Vite 8 + OxLint/OxFmt; remove ESLint/Prettier stack
- **v1.8.0** `feat` [#38](https://github.com/Dark-Avian-Labs/Auth/pull/38): migrate repo to **pnpm**
- **v1.8.1** `chore` [#39](https://github.com/Dark-Avian-Labs/Auth/pull/39): README refresh; dotenvx bump; TS build-info paths
- **v1.8.2** `fix` [#41](https://github.com/Dark-Avian-Labs/Auth/pull/41): Copilot autofix for `run-quality-checks.mjs`
- **v1.8.3** `fix` [#40](https://github.com/Dark-Avian-Labs/Auth/pull/40): Copilot autofix for auth avatar typing
- **v1.8.4** `chore` [#42](https://github.com/Dark-Avian-Labs/Auth/pull/42): cleanup after autofix PRs
- **v1.8.5** `chore` [#45](https://github.com/Dark-Avian-Labs/Auth/pull/45): dependency updates; TS `ES2024`; Tailwind VS Code metadata
- **v1.8.6** `ci` [#43](https://github.com/Dark-Avian-Labs/Auth/pull/43): bump `pnpm/action-setup` v4 → v5 (Dependabot)
- **v1.8.7** `chore` [#46](https://github.com/Dark-Avian-Labs/Auth/pull/46): merge `development` → `main`
- **v1.8.8** `chore` [#47](https://github.com/Dark-Avian-Labs/Auth/pull/47): bump `node-addon-api` via lockfile
- **v1.8.9** `chore` [#48](https://github.com/Dark-Avian-Labs/Auth/pull/48): bump dotenvx / vitest / vite / coverage tooling
- **v1.9.0** `feat` [#49](https://github.com/Dark-Avian-Labs/Auth/pull/49): theme system + selectable UI styles (prism/shadow)
- **v1.9.1** `fix` [#50](https://github.com/Dark-Avian-Labs/Auth/pull/50): theme UX tweaks; profile mode pill + style controls
- **v1.9.2** `fix` [#51](https://github.com/Dark-Avian-Labs/Auth/pull/51): cookie-backed shared theme defaults across apps
- **v1.9.3** `fix` [#52](https://github.com/Dark-Avian-Labs/Auth/pull/52): `FormSelect` portal menu positioning + click-outside behavior
- **v1.10.0** `feat` [#53](https://github.com/Dark-Avian-Labs/Auth/pull/53): HTML boot script for theme; a11y/CSS polish; dependency bumps
- **v1.10.1** `chore` [#54](https://github.com/Dark-Avian-Labs/Auth/pull/54): Dependabot daily; drop legacy deploy workflows; CI env tweaks
- **v1.10.2** `ci` [#55](https://github.com/Dark-Avian-Labs/Auth/pull/55): bump `actions/cache` v4 → v5 (Dependabot)
- **v1.10.3** `fix` [#56](https://github.com/Dark-Avian-Labs/Auth/pull/56): GitHub Actions runner/workflow fixes
- **v1.10.4** `fix` [#57](https://github.com/Dark-Avian-Labs/Auth/pull/57): move inline theme init to `theme-init.js`
- **v1.11.0** `feat` [#61](https://github.com/Dark-Avian-Labs/Auth/pull/61): new deploy workflow shape; bump express-rate-limit, router, linters
- **v1.11.1** `chore` [#62](https://github.com/Dark-Avian-Labs/Auth/pull/62): bump `oxfmt` (Dependabot dev group)
- **v1.11.2** `chore` [#63](https://github.com/Dark-Avian-Labs/Auth/pull/63): point process manager env file at `.env.production`
- **v1.11.3** `chore` [#64](https://github.com/Dark-Avian-Labs/Auth/pull/64): CodeQL-driven refactors; safer theme init + path handling
- **v1.11.4** `chore` [#65](https://github.com/Dark-Avian-Labs/Auth/pull/65): remove unnecessary `FormSelect` comments
- **v1.11.5** `chore` [#66](https://github.com/Dark-Avian-Labs/Auth/pull/66): bump `@dotenvx/dotenvx` (Dependabot production group)
- **v1.11.6** `chore` [#67](https://github.com/Dark-Avian-Labs/Auth/pull/67): bump Vite patch release
- **v1.11.7** `chore` [#68](https://github.com/Dark-Avian-Labs/Auth/pull/68): `FormSelect` empty-state label; safer cookie parsing in theme init
- **v1.11.8** `chore` [#69](https://github.com/Dark-Avian-Labs/Auth/pull/69): listener options cleanup; simpler theme class toggling
- **v1.11.9** `chore` [#70](https://github.com/Dark-Avian-Labs/Auth/pull/70): guard dropdown close targets; clearer cookie decode errors
- **v1.11.10** `chore` [#71](https://github.com/Dark-Avian-Labs/Auth/pull/71): stricter cookie value normalization for theme boot
- **v1.11.11** `chore` [#72](https://github.com/Dark-Avian-Labs/Auth/pull/72): consolidate cookie + `localStorage` theme reads
- **v1.11.12** `chore` [#73](https://github.com/Dark-Avian-Labs/Auth/pull/73): bump `@dotenvx/dotenvx` patch (Dependabot)
- **v1.11.13** `chore` [#74](https://github.com/Dark-Avian-Labs/Auth/pull/74): bump vitest/vite/oxfmt/oxlint/coverage (Dependabot dev group)
- **v1.11.14** `chore` [#75](https://github.com/Dark-Avian-Labs/Auth/pull/75): refresh CI helper scripts
- **v1.11.15** `chore` [#76](https://github.com/Dark-Avian-Labs/Auth/pull/76): remove stray comments (post-review)
- **v1.11.16** `chore` [#77](https://github.com/Dark-Avian-Labs/Auth/pull/77): broad dependency refresh
- **v1.11.17** `chore` [#80](https://github.com/Dark-Avian-Labs/Auth/pull/80): dependency bump batch
- **v1.11.18** `ci` [#81](https://github.com/Dark-Avian-Labs/Auth/pull/81): bump `pnpm/action-setup` to v6 (Dependabot)
- **v1.12.0** `feat` [#82](https://github.com/Dark-Avian-Labs/Auth/pull/82): overhaul CI/CD + validation workflow wiring
- **v1.12.1** `chore` [#83](https://github.com/Dark-Avian-Labs/Auth/pull/83): production dependency bumps (Dependabot)
- **v1.12.2** `chore` [#84](https://github.com/Dark-Avian-Labs/Auth/pull/84): normalize `pnpm-lock.yaml` formatting
- **v1.12.3** `chore` [#85](https://github.com/Dark-Avian-Labs/Auth/pull/85): bump pinned pnpm / toolchain metadata
- **v1.12.4** `fix` [#86](https://github.com/Dark-Avian-Labs/Auth/pull/86): repair CI failures from workflow/tooling drift
- **v1.12.5** `fix` [#87](https://github.com/Dark-Avian-Labs/Auth/pull/87): auth/session regression fixes
- **v1.12.6** `chore` [#88](https://github.com/Dark-Avian-Labs/Auth/pull/88): Opus review tidy-ups
- **v1.13.0** `feat` [#89](https://github.com/Dark-Avian-Labs/Auth/pull/89): rename app identifiers / branding surfaces
- **v1.13.1** `fix` [#90](https://github.com/Dark-Avian-Labs/Auth/pull/90): ecosystem / process manager config corrections
- **v1.13.2** `fix` [#91](https://github.com/Dark-Avian-Labs/Auth/pull/91): naming + SQLite schema alignment fixes
- **v1.13.3** `chore` [#92](https://github.com/Dark-Avian-Labs/Auth/pull/92): automated version bump metadata sync
- **v1.13.4** `chore` [#93](https://github.com/Dark-Avian-Labs/Auth/pull/93): dependency updates
- **v1.13.5** `chore` [#94](https://github.com/Dark-Avian-Labs/Auth/pull/94): relicense / license documentation update
- **v1.14.0** `feat` [#95](https://github.com/Dark-Avian-Labs/Auth/pull/95): upgrade GitHub Actions runner sizing for heavy jobs
- **v1.14.1** `chore` [#96](https://github.com/Dark-Avian-Labs/Auth/pull/96): dependency updates
- **v1.15.0** `feat` [#97](https://github.com/Dark-Avian-Labs/Auth/pull/97): upgrade toolchain to **pnpm v11**
- **v1.16.0** `feat` [#98](https://github.com/Dark-Avian-Labs/Auth/pull/98): improve automated tests (coverage + quality)
- **v1.17.0** `feat` [#99](https://github.com/Dark-Avian-Labs/Auth/pull/99): Discord notifications for CI results
- **v1.18.0** `feat` [#100](https://github.com/Dark-Avian-Labs/Auth/pull/100): adopt Material Symbols for UI icons
- **v1.19.0** `feat` [#101](https://github.com/Dark-Avian-Labs/Auth/pull/101): remove profile avatar image/icons path
- **v1.19.1** `chore` [#103](https://github.com/Dark-Avian-Labs/Auth/pull/103): production dependency bumps (Dependabot)
- **v1.19.2** `chore` [#105](https://github.com/Dark-Avian-Labs/Auth/pull/105): dependency updates
- **v1.19.3** `chore` [#107](https://github.com/Dark-Avian-Labs/Auth/pull/107): dependency updates
- **v1.19.4** `chore` [#109](https://github.com/Dark-Avian-Labs/Auth/pull/109): dependency updates
- **v1.20.0** `feat` [#111](https://github.com/Dark-Avian-Labs/Auth/pull/111): expand security audit automation/reporting in CI
- **v1.21.0** `feat` [#112](https://github.com/Dark-Avian-Labs/Auth/pull/112): semantic-release style CI versioning workflow
- **v1.22.0** `feat` [#114](https://github.com/Dark-Avian-Labs/Auth/pull/114): surface deployed version in UI + prompt reload on updates
- **v1.23.0** `feat` [#116](https://github.com/Dark-Avian-Labs/Auth/pull/116): animated login background treatment
- **v1.23.1** `chore` [#118](https://github.com/Dark-Avian-Labs/Auth/pull/118): CodeQL workflow/config maintenance
- **v1.23.2** `fix` [#119](https://github.com/Dark-Avian-Labs/Auth/pull/119): background animation regressions
- **v1.24.0** `feat` [#120](https://github.com/Dark-Avian-Labs/Auth/pull/120): reworked background animation implementation
- **v1.25.0** `feat` [#121](https://github.com/Dark-Avian-Labs/Auth/pull/121): color overlay controls for background animation
- **v1.25.1** `fix` [#123](https://github.com/Dark-Avian-Labs/Auth/pull/123): correct background ASCII art asset
- **v1.25.2** `chore` [#124](https://github.com/Dark-Avian-Labs/Auth/pull/124): dependency + CodeQL maintenance batch
- **v1.26.0** `feat` [#127](https://github.com/Dark-Avian-Labs/Auth/pull/127): rework permissions model + admin enforcement
- **v1.26.1** `chore` [#126](https://github.com/Dark-Avian-Labs/Auth/pull/126): production dependency bumps (Dependabot; merged after #127 on `main`)
- **v1.26.2** `chore` [#128](https://github.com/Dark-Avian-Labs/Auth/pull/128): new CI workflow layout / wiring
- **v1.26.3** `fix` [#129](https://github.com/Dark-Avian-Labs/Auth/pull/129): login + refresh control behavior
- **v1.26.4** `fix` [#131](https://github.com/Dark-Avian-Labs/Auth/pull/131): theme color / token fixes
- **v1.26.5** `chore` [#132](https://github.com/Dark-Avian-Labs/Auth/pull/132): dependency updates
- **v1.26.6** `chore` [#133](https://github.com/Dark-Avian-Labs/Auth/pull/133): MaterialSymbol in FormSelect
- **v1.26.7** `chore` [#134](https://github.com/Dark-Avian-Labs/Auth/pull/134): feathers icon PNG → SVG in Layout
- **v1.26.8** `chore(deps)` [#135](https://github.com/Dark-Avian-Labs/Auth/pull/135): update oxfmt and oxlint
- **v1.26.9** `chore`: Update dependencies
