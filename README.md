# Vigilant-API

Automated API security scanner that detects logic-layer vulnerabilities across REST APIs using OpenAPI/Swagger specifications and multi-user differential testing.

Built as part of the **32-Week AppSec Roadmap** by **rootverdict**.

---

## What It Does

Vigilant-API performs black-box security testing against live API endpoints. It parses an OpenAPI spec, authenticates as multiple users, and runs a battery of security checks looking for:

- **BOLA / IDOR** — Broken Object Level Authorization (unauthorized access to other users' resources)
- **SSRF** — Server-Side Request Forgery (server fetching attacker-controlled URLs)
- **OAuth 2.0 Flaws** — Logic errors in OAuth implementation

Every finding is saved as a timestamped forensic evidence file. At the end of the scan, both a JSON report (CI/CD-friendly) and an HTML report (human-readable) are generated.

---

## V1 Feature Set

### 1. OpenAPI Spec Parser
Reads YAML or JSON OpenAPI 3.x specs and extracts:
- Base URL from `servers[0].url`, including server-variable defaults
- All endpoints: method, path, parameters, and nested request-body fields
- Security schemes (`BearerAuth`, `ApiKeyAuth`, `OAuth2`)
- Local in-document and external-file `$ref` values
- ID parameters (path params containing "id") for BOLA targeting
- URL parameters (params containing url/uri/redirect/callback/webhook/target/host/proxy) for SSRF targeting

### 2. Authentication Handler
Supports three authentication schemes:

| Scheme | How it works |
|--------|-------------|
| Bearer JWT | Sends raw token in `Authorization: Bearer {token}` |
| API Key | OpenAPI-declared header, query, or cookie location |
| OAuth 2.0 | Supplied tokens, refresh tokens, password grant, or client credentials |

Additional capability: JWT algorithm weakness detection — inspects token headers for `alg=none` (CRITICAL) or `alg=HS256` (INFO — informational, not a confirmed vulnerability).

### 3. BOLA / IDOR Detector — 5 Sub-Checks

#### Simple IDOR
Classic differential test. Every user attempts to read every other user's resource by ID.
- User A (owner) fetches resource → stores response as baseline
- User B (non-owner) fetches same resource → if 200 + similar body → **HIGH**

#### Parameter Pollution IDOR
Sends each declared ID-like query parameter twice, for example
`?account_id=victim_id&account_id=attacker_id`, in both orderings. Any path
parameters on the same operation are filled from their OpenAPI example/default.
Tests whether the server processes the first or last value, potentially bypassing authorization.
Severity: **MEDIUM**

#### Body IDOR
POST/PUT requests with another user's ID in the request body.
Tests 19 field name patterns in both snake_case and camelCase:
`user_id`, `account_id`, `from_account_id`, `owner_id`, `customer_id`, `profile_id`,
`resource_id`, `object_id`, `entity_id`, `record_id`, `subject_id`, `target_id`,
`userId`, `accountId`, `ownerId`, `customerId`, `profileId`, `resourceId`, `objectId`, `entityId`
Severity: **HIGH**

#### Indirect Reference Enumeration
Encodes the resource ID in 4 predictable formats and tests each:

| Encoding | Example (ID = 1) |
|----------|-----------------|
| Base64 | `MQ==` |
| URL-safe Base64 | `MQ` |
| Zero-padded hex | `00000001` |
| MD5 | `c4ca4238a0b923820dcc509a6f75849b` |

If the server accepts an encoded ID and returns real data for an unauthorized user → **MEDIUM**

#### Mass Assignment
Sends privileged fields in POST/PUT/PATCH body and checks if the server accepts them (reflects them back in the response). Tests 16 payload groups across three HTTP methods:

| Category | Fields tested |
|----------|--------------|
| Role escalation | `role`, `is_admin`, `admin`, `user_type`, `permissions`, `scope` |
| Financial | `balance`, `credit`, `credits` |
| Verification bypass | `verified`, `email_verified`, `phone_verified`, `is_verified` |
| Tier escalation | `subscription`, `account_type`, `plan` |

Detection: server returns 200/201 and the privileged field is reflected with the sent value.
Severity: **MEDIUM** (reflection only — persistence not verified; confirm manually before treating as HIGH)

### 4. SSRF Detector — 5 Sub-Checks

Payloads are injected into every parameter the scanner classifies as URL-accepting (`url`, `uri`, `redirect`, `callback`, `webhook`, `target`, `host`, `proxy` keywords). Parameters can be delivered as query strings, path segments, request headers, or cookie values — the detector handles all four injection locations correctly.

#### Basic SSRF
Injects cloud metadata endpoints into URL-accepting parameters and checks if the response contains metadata patterns (AWS keys, AMI IDs, GCP markers, Azure markers, raw `169.254.169.254`).
Targets: AWS IMDSv1, GCP, Azure metadata endpoints.
Severity: **CRITICAL**

#### Blind SSRF
Injects your Burp Collaborator or ngrok callback URL and checks for an in-band reflection of the URL in the server response body. This is a **weak, unconfirmed signal only** — a server may fetch the URL without echoing it back. Confirmation requires an actual DNS/HTTP hit on your out-of-band listener.
Skipped entirely if `--callback` is not provided.
Severity: **LOW** (unconfirmed in-band signal — escalate to HIGH/CRITICAL only after OOB listener confirms outbound request)

#### SSRF via Redirect / Filter Bypass
Injects URLs that bypass IP-based filters by using alternative representations:
- DNS rebinding-style: `169.254.169.254.nip.io`
- IPv6 mapped: `[::ffff:169.254.169.254]`
- Localhost bypass: `0.0.0.0`
- Authority trick: `localhost@169.254.169.254`

Severity: **CRITICAL**

#### Protocol Smuggling
Tests non-HTTP schemes that some server-side fetch implementations support:
`file:///etc/passwd`, `dict://localhost:11211/`, `gopher://localhost:6379/_`, `ftp://localhost:21/`.
A finding requires a protocol-specific response signature (such as a passwd
record, Memcached response, Redis response, or FTP banner); generic text such
as `localhost` is not treated as proof.
Severity: **CRITICAL**

#### Partial SSRF (Filter Bypass)
Tests URL encoding tricks against partial filters:
- Authority bypass: `169.254.169.254@trusted.com`
- Fragment trick: `trusted.com#@169.254.169.254`
- Tab encoding: `169.254.169.254%09`

Severity: **HIGH**

### 5. OAuth Flaw Detector — 5 Sub-Checks

| Check | What it tests | Severity | Notes |
|-------|--------------|----------|-------|
| OAuth state integrity | Supplied `state` is missing or changed in the authorization response | HIGH | General |
| Token leakage in URL | `access_token` in URL fragment/query → Referer header leak | HIGH | Mock-server only † |
| Improper scope validation | Request `read:own`, check exact returned scope tokens for `admin`/`write`/`read:all` | HIGH | General |
| Authorization code reuse | Same auth code submitted twice → RFC 6749 violation | HIGH | Mock-server only † |
| Open redirect abuse | Parsed redirect destination exactly matches an unregistered `redirect_uri` → auth code theft | CRITICAL | General |

> **†  Mock-server only:** The "Token Leakage" and "Authorization Code Reuse" checks use synthetic payloads (`grant_type=implicit_test`, a hardcoded test code) that only match the Vigilant-API mock server.  Against a real OAuth server these checks will return no findings — a negative result does **not** confirm the server is secure.  Full coverage for these checks requires browser automation (Selenium/Playwright) to capture live codes; that is planned for V2.

Also runs JWT algorithm checks on every user token provided:
- `alg=none` → **CRITICAL** (unsigned tokens accepted)
- `alg=HS256` → **INFO** (valid algorithm; flagged as informational — use RS256/ES256 in multi-service architectures)

### 6. Forensic Logger
Every finding is saved as a timestamped JSON evidence file in `reports/evidence/`:

```
evidence_20240115_143022_BOLA_IDOR_A1B2C3D4.json
```

Each file contains:
- `metadata` — finding ID (UUID short), timestamp, tool version
- `vulnerability` — type, check name, severity, endpoint, parameter, resource ID
- `http` — reconstructed request (endpoint, injected param, injected value, curl-style reproduction hint) and response (status code, body preview) for manual reproduction
- `evidence` — raw payload, HTTP status code, response body preview
- `description` — human-readable explanation of the vulnerability
- `remediation` — specific fix guidance

### 7. Report Generator

**JSON Report** (`reports/report.json`)
Machine-readable. Contains scan metadata, severity summary, and full findings array. Designed for CI/CD pipeline integration.

**HTML Report** (`reports/report.html`)
Dark-themed human-readable report containing:
- Executive summary with severity counts (CRITICAL / HIGH / MEDIUM / LOW)
- Findings table with type, check name, severity badge, endpoint, parameter
- Per-finding evidence (payload, response preview)
- Per-finding remediation guidance
- Links to individual evidence JSON files

### 8. CLI Interface
Full-featured Click-based CLI with safe/active modes and a hard request budget. See [Usage](#usage) section.

### 9. Mock Flask Server
Intentionally vulnerable Flask server for local testing with 10 vulnerable endpoints and 2 secure comparison endpoints.

---

## Project Structure

```
vigilant-api/
├── cli.py                        # Main entry point — run from here
├── pyproject.toml                # Build config + pytest settings
├── requirements.txt              # Bounded runtime dependencies
├── requirements-dev.txt          # Test, lint, type, and coverage tools
├── LICENSE                       # MIT licence
├── README.md                     # This file
├── .gitignore                    # Excludes venv/, reports/, evidence/, __pycache__
│
├── src/
│   ├── __init__.py
│   ├── scanner.py                # Orchestrator — wires everything together
│   ├── spec_parser.py            # OpenAPI YAML/JSON parser + $ref resolver
│   ├── auth.py                   # Auth handler + JWT algorithm inspection
│   ├── bola_detector.py          # BOLA/IDOR — 5 sub-checks
│   ├── ssrf_detector.py          # SSRF — 5 sub-checks
│   ├── oauth_detector.py         # OAuth flaws — 5 sub-checks
│   ├── request_utils.py          # Shared hard request budget
│   ├── logger.py                 # Forensic evidence file writer
│   └── reporter.py               # HTML + JSON report generator (Jinja2, autoescape)
│
├── mock_server/
│   ├── __init__.py
│   └── app.py                    # Intentionally vulnerable Flask server (port 5000)
│
├── scripts/
│   ├── __init__.py
│   └── refresh_dummyjson_tokens.py   # Fetch fresh JWTs from dummyjson.com
│
├── tests/
│   ├── __init__.py
│   ├── test_auth.py              # JWT and request-authentication tests
│   ├── test_bola_detector.py     # Differential detection and safety tests
│   ├── test_integration.py       # Full scan against live mock server (port 5099)
│   ├── test_oauth_detector.py    # OAuth detector tests
│   ├── test_spec_parser.py       # Parameters, bodies, variables, and $ref tests
│   └── test_ssrf_detector.py     # Pattern and request-dispatch tests
│
└── sample_specs/
    ├── fintech.yaml              # OpenAPI 3.0.3 test spec for mock server (10 endpoints)
    ├── tokens.json               # Three mock server test tokens (alice, bob, admin)
    ├── oauth_config.json         # OAuth config pointing at mock server OAuth endpoints
    ├── dummyjson.yaml            # OpenAPI spec for dummyjson.com (real external API)
    └── dummyjson_tokens.json     # JWT tokens for dummyjson.com (gitignored — expire after 60 min)
```

---

## Requirements

- Python 3.10+
- pip packages (runtime dependencies are bounded in `requirements.txt`)

```
requests>=2.31,<3
pyyaml>=6.0,<7
jinja2>=3.1,<4
flask>=3.0,<4
click>=8.1,<9
colorama>=0.4.6,<1
PyJWT>=2.8,<3
```

---

## Installation

```bash
git clone https://github.com/rootverdict/vigilant-api.git
cd vigilant-api
pip install -r requirements.txt
```

Or install as an editable package (also installs the `vigilant-api` CLI entry point defined in `pyproject.toml`):

```bash
pip install -e .
```

For development tooling (tests, coverage, Ruff, and mypy):

```bash
pip install -e ".[dev]"
```

---

## Usage

### Start the mock server (Terminal 1)

```bash
python mock_server/app.py
# Listening on http://localhost:5000
```

### Run a scan (Terminal 2)

```bash
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json
```

The default is **safe mode**: only read-only HTTP methods are probed. Add
`--active` only when you have authorization to create or modify target data.

### All CLI options

```
Options:
  --spec           PATH     Path to OpenAPI YAML/JSON spec file        [required]
  --tokens         PATH     Path to JSON file with user tokens          [required]
  --ids            TEXT     Comma-separated resource IDs to probe       [default: 1,2,3,4,5]
  --output         DIR      Directory for report output                 [default: reports]
  --skip           TEXT     Skip check type: bola | ssrf | oauth | jwt  [repeatable]
  --callback       URL      Blind SSRF callback (Burp Collaborator/ngrok). Omit to skip blind SSRF.
  --oauth-config   PATH     JSON file with OAuth server config
  --delay          FLOAT    Seconds between requests (rate limiting)    [default: 0.0]
  --insecure               Disable TLS certificate verification
  --proxy          URL      HTTP proxy for all requests (e.g. Burp Suite)
  --verbose                Print every request URL and payload
  --active                 Enable write-method probes; may modify target data
  --max-requests    INT     Hard request cap                         [default: 1000]
  --version / -V           Show version and exit
```

### Common scan recipes

```bash
# Full active scan — all categories against the intentionally vulnerable mock server
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --oauth-config sample_specs/oauth_config.json --active

# BOLA only — skip SSRF and OAuth
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --skip ssrf --skip oauth

# SSRF only — skip BOLA and OAuth
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --skip bola --skip oauth

# OAuth only — skip BOLA and SSRF
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --skip bola --skip ssrf --oauth-config sample_specs/oauth_config.json

# Verbose mode — see every request being made
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json --verbose

# Rate-limited scan — 500ms between requests (avoids WAF triggers)
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json --delay 0.5

# Route through Burp Suite for manual inspection
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --proxy http://127.0.0.1:8080

# Blind SSRF with Burp Collaborator callback
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --callback https://YOUR_ID.burpcollaborator.net

# Self-signed TLS target
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json --insecure

# Custom resource IDs and output directory
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --ids 1,2,3,10,50,99 --output my_pentest_reports

# Cap a safe reconnaissance scan at 250 HTTP requests
python cli.py --spec api.yaml --tokens tokens.json --max-requests 250

# Full scan with all options
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --oauth-config sample_specs/oauth_config.json \
  --delay 0.3 --proxy http://127.0.0.1:8080 \
  --callback https://YOUR_ID.burpcollaborator.net \
  --active --max-requests 1000 --verbose --output reports
```

---

## Token File Format

`sample_specs/tokens.json`:

```json
[
  {"name": "alice", "token": "token_alice", "user_id": 1},
  {"name": "bob",   "token": "token_bob",   "user_id": 2},
  {"name": "admin", "token": "token_admin", "user_id": 9}
]
```

At minimum two users are required for differential testing. Ownership is inferred
from response fields such as `owner_id`/`user_id`, or can be declared with a
`resource_ids` array. Privileged accounts can be marked with `"role": "admin"`
or `"owns_all": true`; they are never used as unauthorized attackers. If ownership cannot be established,
Vigilant-API skips the high-confidence Simple IDOR verdict instead of guessing.

API keys use the location and name from the operation's OpenAPI security scheme:

```json
[
  {"name": "service-a", "scheme": "apiKey", "key": "secret-a", "user_id": 1},
  {"name": "service-b", "scheme": "apiKey", "key": "secret-b", "user_id": 2}
]
```

OpenAPI security requirements are honored correctly: schemes within one object
are combined with AND, while separate requirement objects are treated as OR
alternatives. For multiple named API keys, use `"api_keys": {"SchemeName": "value"}`.

OAuth users can provide `access_token` directly or provide `token_url`,
`client_id`, and either password or client credentials. Tokens are refreshed
automatically when a `refresh_token` is present.

---

## OAuth Config File Format

Required only when using `--oauth-config`.

**Local mock server** (use `sample_specs/oauth_config.json` — works out of the box):

```json
{
  "auth_url":      "http://localhost:5000/oauth/authorize",
  "token_url":     "http://localhost:5000/oauth/token",
  "client_id":     "vigilant-test-client",
  "client_secret": "vigilant-test-secret",
  "redirect_uri":  "http://localhost:5000/callback"
}
```

**Real OAuth server** (point at your own auth server):

```json
{
  "auth_url":      "https://your-auth-server.com/oauth/authorize",
  "token_url":     "https://your-auth-server.com/oauth/token",
  "client_id":     "your_client_id",
  "client_secret": "your_client_secret",
  "redirect_uri":  "http://localhost/callback"
}
```

Required keys: `auth_url`, `token_url`, `client_id`. All others are optional.

---

## Output

After a scan, the `reports/` directory contains:

```
reports/
├── report.json              # Machine-readable full report
├── report.html              # Human-readable HTML report
└── evidence/
    ├── evidence_20240115_143022_BOLA_IDOR_A1B2C3D4.json
    ├── evidence_20240115_143025_SSRF_B5C6D7E8.json
    └── ...                  # One file per finding
```

### Console output

```
============================================================
  Vigilant-API v1.0 — API Security Scanner
  Target    : http://localhost:5000
  Endpoints : 10
  Delay     : 0.0s  |  Verify TLS: True
  Proxy     : none
  Callback  : none (blind SSRF skipped)
  Mode      : SAFE (read-only methods)
  Budget    : 1000 requests
============================================================

  GET     /transactions/{id}
    [HIGH] Simple IDOR
           Evidence -> reports/evidence/evidence_..._A1B2.json
  POST    /transfer
    [HIGH] Body IDOR
           Evidence -> reports/evidence/evidence_..._C3D4.json

============================================================
  Scan Complete — 3 finding(s)
  CRITICAL: 0  HIGH: 2  MEDIUM: 1  LOW: 0  INFO: 0

  JSON report : reports/report.json
  HTML report : reports/report.html
============================================================
```

### CI/CD integration

The scanner exits with code `1` if any CRITICAL or HIGH findings exist, and `0` if the scan is clean. Plug it directly into a pipeline gate:

```yaml
# GitHub Actions example
- name: API Security Scan
  run: python cli.py --spec api-spec.yaml --tokens tokens.json
```

### Development checks

The same checks run automatically in GitHub Actions on Python 3.10 and 3.12:

```bash
ruff check .
mypy
pytest --cov=src --cov-report=term-missing
```

Coverage must remain at or above 70%. The local pre-commit configuration runs
Ruff and mypy before changes are committed.

---

## Testing Against an External API (DummyJSON)

Vigilant-API can run against any real public or private API that has an OpenAPI spec. [DummyJSON](https://dummyjson.com) is a free fake REST API that intentionally has no access control — perfect for verifying the scanner works end-to-end against a live target.

### Step 1 — Refresh tokens (required — tokens expire after 60 minutes)

```bash
python scripts/refresh_dummyjson_tokens.py
```

This fetches fresh JWTs for three test users (`emilys`, `michaelw`, `sophiab`) and writes them to `sample_specs/dummyjson_tokens.json`.

### Step 2 — Run the scan

```bash
python cli.py \
  --spec sample_specs/dummyjson.yaml \
  --tokens sample_specs/dummyjson_tokens.json \
  --skip ssrf \
  --delay 0.2 \
  --ids 1,2,3
```

`--skip ssrf` is recommended for external APIs you don't own — SSRF probes inject metadata URLs which are irrelevant to dummyjson and just add noise. `--delay 0.5` prevents rate-limiting.

### What to expect

- **JWT algorithm findings** — all three dummyjson tokens use `HS256` → 3 x INFO findings (informational, not a confirmed vulnerability)
- **Simple IDOR findings** — dummyjson returns any user's data to any authenticated token → multiple HIGH findings across `/users/{id}`, `/posts/{id}`, `/carts/{id}`, `/todos/{id}`
- **Body IDOR / Mass Assignment** — DummyJSON echoes back PUT body fields, which will trigger findings
- **Estimated runtime** — 2-4 minutes with `--delay 0.2 --ids 1,2,3` (varies with dummyjson.com server load)

---

## Mock Server Endpoints

Run `python mock_server/app.py` to start a local vulnerable server on port 5000.

### Vulnerable endpoints

| Method | Path | Vulnerability | Check triggered |
|--------|------|--------------|----------------|
| GET | `/transactions/{id}` | No ownership check — any token reads any record | Simple IDOR |
| GET | `/profile/{user_id}` | No ownership check — leaks any user profile | Simple IDOR |
| GET | `/fetch?url=` | Fetches any URL without allowlist — simulates cloud metadata response (query param) | Basic SSRF, SSRF via Redirect, Partial SSRF |
| GET | `/proxy` | Fetches any URL from `X-Target-URL` request header without allowlist (header param) | Basic SSRF, SSRF via Redirect, Partial SSRF |
| POST | `/transfer` | Accepts any `from_account_id` without verifying ownership | Body IDOR |
| GET | `/export?id=` | Uses last `id` value when duplicated | Parameter Pollution |
| GET | `/resource/<ref>` | Decodes base64/hex/int ID with no ownership check | Indirect Reference |
| POST/PUT/PATCH | `/user/update` | Merges all request fields including privileged ones | Mass Assignment, Body IDOR |
| GET | `/oauth/authorize` | Accepts any `redirect_uri` | Open redirect |
| POST | `/oauth/token` | Grants excess scope, accepts reused codes, leaks token in URL redirect | Scope bypass, Code reuse, Token leakage |

### Secure endpoints (for comparison)

| Method | Path | Fix applied |
|--------|------|------------|
| GET | `/secure/transactions/{id}` | Checks `owner_id == current_user_id` before returning |
| POST | `/secure/transfer` | Validates account ownership before processing transfer |

---

## How Each Detector Works

### BOLA — Differential Testing Model

```
alice (token_alice) → GET /transactions/1 → 200 {"id":1, "owner_id":1, "amount":500}
bob   (token_bob)   → GET /transactions/1 → 200 {"id":1, "owner_id":1, "amount":500}
                                                  ↑
                       Same data returned to non-owner = BOLA confirmed (HIGH)
```

### SSRF — Metadata Injection Model

```
Attacker sends:  GET /fetch?url=http://169.254.169.254/latest/meta-data/
Server responds: {"status": 200, "body": "ami-0abcdef1234567890\nami-..."}
                                                ↑
               AWS AMI ID pattern matched in response = SSRF confirmed (CRITICAL)
```

### OAuth — Logic Flaw Probing Model

```
Scanner sends:   GET /authorize?...&state=vigilant-state-integrity-check
Server responds: 302 Location: http://localhost/callback?code=AUTH_CODE
                                                             ↑
               Supplied state missing/changed = state integrity failure (HIGH)
```

---

## Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Immediate compromise possible | SSRF reaching cloud metadata, `alg=none` JWT, OAuth open redirect |
| HIGH | Significant data exposure or privilege escalation | Simple IDOR, Body IDOR, Partial SSRF |
| MEDIUM | Limited impact or requires chaining | Parameter Pollution, Indirect Reference, Mass Assignment (reflection only) |
| LOW | Unconfirmed signal — manual verification needed | Blind SSRF (in-band signal only) |
| INFO | Informational — not a confirmed vulnerability | HS256 JWT algorithm (valid but worth noting) |

---

## Remediation Summary

| Vulnerability | Fix |
|--------------|-----|
| BOLA / IDOR | Verify `authenticated_user.id == resource.owner_id` on every request |
| Parameter Pollution | Accept only a single value per parameter; reject duplicates |
| Body IDOR | Server must derive the subject ID from the auth token, never from the request body |
| Indirect Reference | Use random UUIDs (v4); enforce ownership checks regardless of reference format |
| Mass Assignment | Allowlist permitted fields (DTO pattern); strip all others before processing |
| Basic / Redirect SSRF | Allowlist permitted destination IPs/domains; block RFC 1918 and 169.254.169.254 |
| Blind SSRF | Same as above; also disable server-side redirects in fetch calls |
| Protocol Smuggling | Block non-HTTP(S) schemes at the application layer |
| OAuth — State integrity | Echo the exact client-supplied `state`; clients must validate it on callback |
| OAuth — Token in URL | Use auth code flow with PKCE; never put tokens in URLs |
| OAuth — Scope bypass | Server must enforce scope restrictions; never grant broader than requested |
| OAuth — Code reuse | Auth codes must be single-use; invalidate on first exchange |
| OAuth — Open redirect | Validate `redirect_uri` against a strict pre-registered allowlist |
| JWT `alg=none` | Reject tokens with `alg=none`; enforce an algorithm allowlist |
| JWT HS256 | Prefer RS256 / ES256; if HS256, use a 256-bit+ random secret |

---

## Architecture

```
cli.py
  └── Scanner
        ├── OpenAPIParser      ← reads spec, extracts endpoints + params
        ├── BOLADetector       ← 5 IDOR checks per endpoint
        │     ├── _simple_idor
        │     ├── _param_pollution
        │     ├── _body_idor
        │     ├── _indirect_reference
        │     └── _mass_assignment
        ├── SSRFDetector       ← 5 SSRF checks per URL param
        │     ├── _basic_ssrf
        │     ├── _blind_ssrf
        │     ├── _redirect_ssrf
        │     ├── _protocol_smuggling
        │     └── _partial_ssrf
        ├── OAuthFlawDetector  ← 5 OAuth checks (if --oauth-config provided)
        │     ├── _check_missing_state
        │     ├── _check_token_leakage_in_url
        │     ├── _check_improper_scope
        │     ├── _check_code_reuse
        │     └── _check_open_redirect
        ├── AuthHandler        ← JWT algorithm checks per user token
        ├── ForensicLogger     ← writes evidence JSON files
        └── ReportGenerator    ← generates report.json + report.html
```

---

## Extending Vigilant-API

### Add a new detector

1. Create `src/my_detector.py` with a class that returns a list of finding dicts
2. Import and instantiate it in `scanner.py`
3. Call it in `Scanner.run()` for each endpoint or globally
4. Each finding dict needs: `type`, `check`, `severity`, `endpoint`, `evidence`, `remediation`

### Add a new BOLA sub-check

1. Add a `_my_check(self, ...)` method to `BOLADetector`
2. Call it from `test_endpoint()`
3. Return a list of finding dicts using the existing `_make_finding()` helper or build directly

### Add a new SSRF payload

Add the URL to the appropriate list constant in `SSRFDetector`:
- Cloud metadata target → `METADATA_URLS`
- Protocol smuggling → `PROTOCOL_PAYLOADS`

---

## Limitations (V1)

- No support for GraphQL or gRPC APIs (REST/OpenAPI only)
- Local external-file `$ref` values are supported; remote HTTP references are deliberately not downloaded and produce a warning
- BOLA Simple IDOR tests path parameters only — query-string-only object IDs (e.g. `GET /export?id=1`) are covered by the Parameter Pollution check, not Simple IDOR
- BOLA checks rely on the spec having parameters declared — undocumented parameters are not discovered
- Active body checks require `--active` and favor high-confidence evidence over speculative findings
- OAuth checks require a reachable authorization server; "Token Leakage" and "Code Reuse" checks are effective only against the bundled mock server (see OAuth section above)
- Blind SSRF detection is an in-band signal only — a negative result does not rule out blind SSRF; use an out-of-band listener (Burp Collaborator, ngrok, interactsh) for confirmation
- No built-in support for multi-step flows or stateful test sequences
- Rate limiting is uniform (same delay for all requests); a shared hard request budget prevents unbounded scans

---

## License

[MIT](./LICENSE) · Built as part of a 32-Week AppSec Roadmap · Author: [rootverdict](https://github.com/rootverdict)

---

*Vigilant-API v1.0*
