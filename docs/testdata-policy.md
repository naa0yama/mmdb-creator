# Test Data Policy

Source code (`.rs` files) **must not** embed real production values.
Use only the approved fictitious values listed below.
Violations are caught by `mise run ast-grep` and `gitleaks`.

---

## IPv4 Addresses

Only RFC-reserved documentation / private ranges are permitted.

| Range             | RFC      | Note                       |
| ----------------- | -------- | -------------------------- |
| `10.0.0.0/8`      | RFC 1918 | Private                    |
| `100.64.0.0/10`   | RFC 6598 | Carrier-grade NAT          |
| `127.0.0.0/8`     | RFC 1122 | Loopback                   |
| `169.254.0.0/16`  | RFC 3927 | Link-local                 |
| `172.16.0.0/12`   | RFC 1918 | Private                    |
| `192.0.2.0/24`    | RFC 5737 | TEST-NET-1                 |
| `192.168.0.0/16`  | RFC 1918 | Private                    |
| `198.51.100.0/24` | RFC 5737 | TEST-NET-2 (**preferred**) |
| `203.0.113.0/24`  | RFC 5737 | TEST-NET-3                 |
| `224.0.0.0/4+`    | RFC 5771 | Multicast / reserved       |

**Preferred address for examples**: `198.51.100.x` (TEST-NET-2).

For CIDR containment tests that need a supernet of TEST-NET-2, use
`10.0.0.0/20` or `10.0.0.0/19` (RFC 1918).

---

## IPv6 Addresses

| Range           | RFC      | Note                 |
| --------------- | -------- | -------------------- |
| `2001:db8::/32` | RFC 3849 | Documentation prefix |

---

## ASNs

| Range       | RFC      |
| ----------- | -------- |
| 64496-64511 | RFC 5398 |

Use `64496` as the canonical single-ASN example.

---

## Domain Names

RFC 2606 and RFC 6761 reserve the following domains for documentation and testing.
Only these domains are permitted in test fixtures and source code.

| Domain / TLD     | RFC      | Permitted use                            |
| ---------------- | -------- | ---------------------------------------- |
| `example.com`    | RFC 2606 | Backbone PTR records, misc hosts         |
| `example.net`    | RFC 2606 | PTR domain-filter miss, whois server     |
| `example.org`    | RFC 2606 | Reserved; available if needed            |
| `.example` TLD   | RFC 2606 | Reserved; not used directly              |
| `.test` TLD      | RFC 2606 | Reserved; not used directly              |
| `.invalid` TLD   | RFC 2606 | Negative-test hostnames (must-not-match) |
| `.localhost` TLD | RFC 6761 | Reserved; not used directly              |

Non-RFC domains such as `example.ad.jp`, `example.ne.jp`, `example.co.jp` are
**not** documentation-reserved and must not appear in source code or fixtures.

---

## Backbone Device Names

These are the **only** approved device segment values for PTR-style FQDNs
and bare `device.facility` identifiers.

```
rtr01   rtr02   rtr03
edge01  edge02  edge03
core01  core02
```

For intentional **negative tests** (device-not-found, non-backbone host),
use a name with a non-backbone prefix: `srv01`, `host01`, `cache01`.
Do **not** use `rtr99`, `edge99`, etc. — numeric suffix tricks confuse the
positive-allowlist check.

---

## Facility Names

```
dc01   dc05
pop1   pop2
```

---

## Approved FQDNs by Domain

### `example.com` — backbone PTR records

Any combination of approved device x facility, optionally preceded by
an interface segment or `user`/`virtual`/`as<ASN>` prefix.

Examples:

```
ge-0-0-0.rtr01.dc01.example.com
xe-0-0-1.rtr01.dc01.example.com
user.xe-0-0-1.rtr01.dc01.example.com
user.virtual.xe-0-0-1.rtr01.dc01.example.com
as64496.xe-0-1-0.rtr03.dc01.example.com
rtr02.dc01.example.com
ge-0-0-0.rtr02.dc01.example.com
xe-0-0-1.edge01.pop1.example.com
```

### `example.net` — PTR domain-filter miss + whois server + RPSL referral

```
whois.example.net
ge-0-0-0.rtr02.dc01.example.net   (domain-filter miss test only)
```

### `example.com` — non-backbone hosts, customer hosts, misc

```
host.example.com
host2.example.com
customer1.example.com
customer2.example.com
unknown.example.com
unknown-host.example.com
whois.example.com
```

Backbone-PTR-style FQDNs under `example.com` are also permitted when
explicitly testing the filter-miss path (no interface segment → should not
be checked as backbone PTR).

### External real domains (implementation config defaults only)

```
whois.iana.org
```

Only in implementation source (e.g., default config values).
Never in test fixtures.

---

## Bare Device.Facility Identifiers

Bare `<device>.<facility>` tokens (e.g., Excel sheet names, struct fields)
must use the same approved device and facility lists above.

```
rtr01.dc01    rtr02.dc01    edge01.pop1    edge01.dc01
edge01.dc05   core01.dc01
```

---

## What Is Not Permitted

- Real production IP addresses or prefixes outside the RFC-reserved ranges
- Real ASNs outside 64496-64511
- Real organisation names (use `EXAMPLE-NET Example Network, Inc.`)
- Real router hostnames (e.g., `medge0306`, `edge0504`)
- Non-`example.*` / non-`iana.org` / non-`.invalid` domains in test fixtures
- `example-rir.net` — not RFC-reserved; use `example.net` or `example.com` instead
- `example.ad.jp`, `example.ne.jp`, `example.co.jp` — not RFC-reserved; use `example.com` or `example.net`
- Supernets of TEST-NET-2 (e.g., `198.51.96.0/20`) — use RFC 1918 supernets

---

## Negative-Test Domains

For hostnames that must **not** match any `example.*` pattern (e.g. domain-filter
miss tests), use the `.invalid` TLD (RFC 2606):

```
host.other.invalid
other.invalid
```

---

## Enforcement

### ast-grep rules — Rust source files (`mise run ast-grep`)

Four rules applied to `.rs` files via ast-grep.

| Rule file          | Detects                                          |
| ------------------ | ------------------------------------------------ |
| `no-real-ipv4.yml` | IPv4 addresses outside RFC-reserved ranges       |
| `no-real-ipv6.yml` | IPv6 addresses outside 2001:db8::/32             |
| `no-real-asn.yml`  | ASNs outside RFC 5398 range AS64496-AS64511      |
| `no-real-fqdn.yml` | PTR hostnames with non-approved device or domain |

Files excluded from testdata scanning: `cymru.rs` (reversed-octet DNS queries),
`integration_test.rs` (live-network fixture data).

### grep rules — text files (`mise run ast-grep`)

Four checks applied to `.md`, `.json`, `.jsonl` files via `grep -P` (ugrep PCRE2).
Runs as part of the same `mise run ast-grep` task.

| Check ID            | Detects                                        |
| ------------------- | ---------------------------------------------- |
| `no-real-ipv4-text` | IPv4 addresses outside RFC-reserved ranges     |
| `no-real-ipv6-text` | IPv6 addresses outside 2001:db8::/32           |
| `no-real-asn-text`  | ASNs outside RFC 5398 range AS64496-AS64511    |
| `no-real-fqdn-text` | Interface-style FQDNs with non-approved domain |

Directories excluded: `data/` (live-network runtime data), `tmp/`.
