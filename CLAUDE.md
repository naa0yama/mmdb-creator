# Project Summary

- Think in English, explain, and respond to chat in Japanese.
- Use half-width brackets instead of full-width brackets in the Japanese explanations output.
- When writing Japanese and half-width alphanumeric characters or codes in one sentence, please enclose the half-width alphanumeric characters in backquotes and leave half-width spaces before and after them.

## Commands

All tasks use `mise run <task>`:

| Task                  | Command                       |
| --------------------- | ----------------------------- |
| Setup                 | `mise run setup`              |
| Build                 | `mise run build`              |
| Build (release)       | `mise run build:release`      |
| Build (timings)       | `mise run build:timings`      |
| Check                 | `mise run check`              |
| Test                  | `mise run test`               |
| TDD watch             | `mise run test:watch`         |
| Doc tests             | `mise run test:doc`           |
| Trace test            | `mise run test:trace`         |
| Format                | `mise run fmt`                |
| Format check          | `mise run fmt:check`          |
| Lint (clippy)         | `mise run clippy`             |
| Lint strict           | `mise run clippy:strict`      |
| Lint                  | `mise run lint`               |
| Lint (GitHub Actions) | `mise run lint:gh`            |
| AST rules             | `mise run ast-grep`           |
| Pre-commit (required) | `mise run pre-commit`         |
| Pre-push              | `mise run pre-push`           |
| Coverage              | `mise run coverage`           |
| Coverage (HTML)       | `mise run coverage:html`      |
| Audit                 | `mise run audit`              |
| Deny (licenses/deps)  | `mise run deny`               |
| Miri (UB detection)   | `mise run miri`               |
| Clean (full)          | `mise run clean`              |
| Clean (sweep)         | `mise run clean:sweep`        |
| Badges (init)         | `mise run badges:init`        |
| Claude Code (install) | `mise run claudecode:install` |
| O2 (install)          | `mise run o2:install`         |
| O2 (start)            | `mise run o2`                 |
| O2 (stop)             | `mise run o2:stop`            |
| Dev (start)           | `mise run dev:up`             |
| Dev (stop)            | `mise run dev:down`           |
| Dev (exec)            | `mise run dev:exec`           |
| Dev (status)          | `mise run dev:status`         |
| Traefik setup         | `mise run traefik:setup`      |

## Commit Convention

Conventional Commits: `<type>: <description>` or `<type>(<scope>): <description>`

Allowed types: feat, update, fix, style, refactor, docs, perf, test, build, ci, chore, remove, revert

## Workflow

1. Write tests (for new features / bug fixes)
2. Implement
3. Run `mise run test` — all tests must pass
4. Stage only the relevant files
5. Run `mise run pre-commit` (runs clean:sweep, fmt:check, clippy:strict, ast-grep, lint:gh)
6. If errors, fix → re-stage → re-run `mise run pre-commit`

## Test / Documentation Data Policy

This project operates on globally-routable IP address space.
Never use real ASNs, real IP prefixes, real organization names, or real
allocation dates in source code (doc comments, test fixtures, examples).
Always use RFC-reserved documentation values:

| Kind         | Reserved range                        | Example                             |
| ------------ | ------------------------------------- | ----------------------------------- |
| IPv4 address | 198.51.100.0/24 (RFC 5737 TEST-NET-2) | `198.51.100.1`                      |
| IPv4 prefix  | 198.51.100.0/24 (RFC 5737 TEST-NET-2) | `198.51.100.0/24`                   |
| IPv6 address | 2001:db8::/32 (RFC 3849)              | `2001:db8::1`                       |
| ASN          | 64496–64511 (RFC 5398)                | `64496`                             |
| Org name     | (fictional)                           | `EXAMPLE-NET Example Network, Inc.` |
| Date         | (fictional, post-2000)                | `2001-01-01`                        |

TEST-NET-2 (198.51.100.x) is preferred over TEST-NET-1 (192.0.2.x) because
it better represents globally-routable (non-private) address space context.

## Code Comments

- Write all code comments (doc comments, inline comments) in concise English.

## Skill Maintenance

- **Global skills** (`~/.claude/skills/`): Shared across all Rust projects. Update these when changing rules that apply universally (error handling, import grouping, test templates, ast-grep rules, workflow agents).
  - `rust-implementation/` — idiomatic Rust patterns (naming, types, errors, testing, CLI design)
  - `rust-project-conventions/` — shared base rules (error context, logging, imports, async)
  - `rust-qa/`, `rust-review/`, `rust-docs/` — QA / review / docs agents
  - `deps-sync/`, `deps-sync-mise/` — dependency sync (language-agnostic)
  - `rust-deps-sync/`, `rust-deps-sync-crates/`, `rust-deps-sync-tests/` — Rust dependency sync
  - `jaeger-trace/`, `o2-trace/` — trace analysis agents
- **Project skills** (`.claude/skills/`): Project-specific overrides only.
  - `project-conventions/` — project name, command table, OTel config, Miri categories, module layout
  - `lib-*/`, `tool-*/` — auto-generated by `/deps-sync`
- When modifying coding rules in `CLAUDE.md`, update the corresponding skill files:
  - Universal rules → `~/.claude/skills/rust-project-conventions/`
  - Project-specific rules → `.claude/skills/project-conventions/`
