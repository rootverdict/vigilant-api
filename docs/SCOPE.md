# Project Scope

Vigilant-API is a black-box, logic-layer security scanner for REST APIs. This
document defines what is delivered (**V1**) and what is planned (**V2**).

Current version: `1.0.0`.

## V1 — Delivered

The core pipeline is complete and works end-to-end: parse an OpenAPI spec →
authenticate as multiple identities → run logic-layer detectors → emit forensic
evidence and reports → return CI exit codes.

| Area | Capabilities | Module |
|---|---|---|
| Spec parsing | OpenAPI 3.x YAML/JSON, server variables, parameters, request bodies, security schemes, local `$ref` files | `src/spec_parser.py` |
| Authentication | Bearer tokens, API keys, OAuth tokens, token refresh, password and client-credentials grants | `src/auth.py` |
| BOLA / IDOR | Simple IDOR, parameter pollution, body IDOR, indirect-reference enumeration, mass assignment | `src/bola_detector.py` |
| SSRF | Cloud-metadata probes, redirect/filter bypass, blind callback, protocol smuggling, partial SSRF | `src/ssrf_detector.py` |
| OAuth 2.0 | State integrity, token-in-URL leakage, scope validation, code reuse, open redirect | `src/oauth_detector.py` |
| JWT | `alg=none` (CRITICAL) and HS256 (INFO) inspection | `src/auth.py` |
| Safety | Read-only default, explicit `--active` write mode, request delay, hard request budget | `src/scanner.py` |
| Reporting | JSON and HTML reports plus per-finding forensic evidence | `src/reporter.py` |
| Integration | CI/CD exit codes (0/1/2), proxy support, `--verbose` | `cli.py` |
| Robustness | Defensive parsing of malformed/hostile specs and JWT headers; scans fail safe instead of crashing | `src/spec_parser.py`, `src/auth.py`, `src/bola_detector.py`, `src/ssrf_detector.py` |
| Dev infrastructure | Intentionally vulnerable mock server, sample specs, test suite, CI on Python 3.10/3.12, ≥70% coverage | `mock_server/`, `tests/` |

### Robustness detail (V1 hardening)

Malformed or hostile inputs are handled without aborting a scan:

- `paths`, `components.securitySchemes`, `servers`, and per-operation objects are
  type-checked before use; non-object entries are skipped, not dereferenced.
- Non-object `servers[0]` and undefined server variables fall back with a warning.
- Non-object parameter entries are skipped during extraction.
- YAML recursive anchors (genuinely cyclic structures) are guarded against
  infinite recursion during `$ref` origin registration.
- JWT `alg` values that are missing, null, or non-string are coerced defensively.
- Auth handlers are cached per identity instead of being rebuilt on every call.

## V2 — Planned

Ordered items are the documented limitations and known gaps; priority is not yet
fixed.

| # | Item | Rationale |
|---|---|---|
| 1 | GraphQL / gRPC support | Today the scanner is REST/OpenAPI only. |
| 2 | Remote HTTP `$ref` download | Only local external `$ref` files are resolved. |
| 3 | Fully automated browser OAuth flow | Token leakage now probes the real implicit grant, and code reuse accepts a real `auth_code` via `--oauth-config` — both work against live servers. Automatically driving the login/consent screen to capture a code (Playwright/Selenium) remains outstanding. |
| 4 | Multi-step stateful workflows | Endpoints are tested in isolation; no login → act → verify chains. |
| 5 | Adaptive / per-endpoint rate limiting | A single uniform delay is applied to all requests. |
| 7 | New vulnerability families | e.g. BFLA (function-level authorization), excessive data exposure, injection, rate-limit abuse. |

Delivered since the original V1 cut:

- **Mass-assignment persistence verification** — after reflection, the BOLA detector
  reads the resource back through a heuristically-paired (or config-supplied) GET
  endpoint; a confirmed persisted privilege field is reported **HIGH**, reflection-only
  stays **MEDIUM**.
- **Real OAuth token-leakage & code-reuse** — see item 3 above.

## Out of scope

- Payload-level scanning already covered by conventional DAST tools.
- Deploying or exposing the mock server outside local testing.
