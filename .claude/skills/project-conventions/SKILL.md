---
name: project-conventions
description: >-
  Project-specific conventions for the mmdb-cli Rust CLI. Overrides
  and extends the shared rust-project-conventions skill with project-specific
  commands, OTel configuration, and project structure. Use when writing,
  reviewing, or modifying .rs files, running builds/tests, or creating commits.
  Complements rust-implementation with project-specific rules.
license: AGPL-3.0
---

# Project Conventions — mmdb-cli (Override)

> **Base rules**: See `~/.claude/skills/rust-project-conventions/SKILL.md` for
> shared conventions (error context, logging, imports, workflow, comments,
> commits, async rules, ast-grep rules).

## Commands: mise Only

Never run `cargo` directly. All tasks go through `mise run`:

| Task           | Command                                   |
| -------------- | ----------------------------------------- |
| Build          | `mise run build`                          |
| Test           | `mise run test`                           |
| TDD watch      | `mise run test:watch`                     |
| Doc tests      | `mise run test:doc`                       |
| Trace test     | `mise run test:trace`                     |
| Format         | `mise run fmt`                            |
| Format check   | `mise run fmt:check`                      |
| Lint (clippy)  | `mise run clippy`                         |
| Lint strict    | `mise run clippy:strict`                  |
| AST rules      | `mise run ast-grep`                       |
| Pre-commit     | `mise run pre-commit`                     |
| Coverage       | `mise run coverage`                       |
| Deny           | `mise run deny`                           |
| Build w/o OTel | `mise run build -- --no-default-features` |

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

## Reference Files

| Topic                      | File                                                                       |
| -------------------------- | -------------------------------------------------------------------------- |
| Testing patterns & Miri    | `references/testing-patterns.md`                                           |
| Project source layout      | `references/module-and-project-structure.md`                               |
| Module structure (shared)  | `~/.claude/skills/rust-project-conventions/references/module-structure.md` |
| ast-grep rules (shared)    | `~/.claude/skills/rust-project-conventions/references/ast-grep-rules.md`   |
| Testing templates (shared) | `~/.claude/skills/rust-coding/references/testing-templates.md`             |
