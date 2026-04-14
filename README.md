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
- Base URL from `servers[0].url`
- All endpoints: method, path, parameters (name, location, required flag)
- Security schemes (`BearerAuth`, `ApiKeyAuth`, `OAuth2`)
- ID parameters (path params containing "id") for BOLA targeting
- URL parameters (params containing url/uri/redirect/callback/webhook/target/host/proxy) for SSRF targeting

### 2. Authentication Handler
Supports three authentication schemes:

| Scheme | How it works |
|--------|-------------|
| Bearer JWT | Sends raw token in `Authorization: Bearer {token}` |
| API Key | Custom header (default: `X-API-Key`) |
| OAuth 2.0 | Resource Owner Password Credentials grant with automatic token refresh |

Additional capability: JWT algorithm weakness detection — inspects token headers for `alg=none` (CRITICAL) or `alg=HS256` (MEDIUM).

### 3. BOLA / IDOR Detector — 5 Sub-Checks

#### Simple IDOR
Classic differential test. Every user attempts to read every other user's resource by ID.
- User A (owner) fetches resource → stores response as baseline
- User B (non-owner) fetches same resource → if 200 + similar body → **HIGH**

#### Parameter Pollution IDOR
Sends duplicate query parameters: `?id=victim_id&id=attacker_id` in both orderings.
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
Encodes the resource ID in 5 predictable formats and tests each:

| Encoding | Example (ID = 1) |
|----------|-----------------|
| Base64 | `MQ==` |
| URL-safe Base64 | `MQ` |
| Zero-padded hex | `00000001` |
| MD5 | `c4ca4238a0b923820dcc509a6f75849b` |
| UUID from int | `00000000-0000-0000-0000-000000000001` |

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
Severity: **HIGH**

### 4. SSRF Detector — 5 Sub-Checks

#### Basic SSRF
Injects cloud metadata endpoints into URL-accepting parameters and checks if the response contains metadata patterns (AWS keys, AMI IDs, GCP markers, Azure markers, raw `169.254.169.254`).
Targets: AWS IMDSv1, GCP, Azure metadata endpoints.
Severity: **CRITICAL**

#### Blind SSRF
Injects your Burp Collaborator or ngrok callback URL. If the server accepts the request without blocking it, logs a potential finding. Requires out-of-band confirmation via your listener.
Skipped entirely if `--callback` is not provided.
Severity: **HIGH**

#### SSRF via Redirect / Filter Bypass
Injects URLs that bypass IP-based filters by using alternative representations:
- DNS rebinding-style: `169.254.169.254.nip.io`
- IPv6 mapped: `[::ffff:169.254.169.254]`
- Localhost bypass: `0.0.0.0`
- Authority trick: `localhost@169.254.169.254`

Severity: **CRITICAL**

#### Protocol Smuggling
Tests non-HTTP schemes that some server-side fetch implementations support:
`file:///etc/passwd`, `file:///etc/hostname`, `dict://localhost:11211/`, `gopher://localhost:6379/_`, `ftp://localhost:21/`
Severity: **CRITICAL**

#### Partial SSRF (Filter Bypass)
Tests URL encoding tricks against partial filters:
- Authority bypass: `169.254.169.254@trusted.com`
- Fragment trick: `trusted.com#@169.254.169.254`
- Tab encoding: `169.254.169.254%09`

Severity: **HIGH**

### 5. OAuth Flaw Detector — 5 Sub-Checks

| Check | What it tests | Severity |
|-------|--------------|----------|
| Missing state parameter | Auth request without `state` → CSRF vulnerability | HIGH |
| Token leakage in URL | `access_token` in URL fragment/query → Referer header leak | HIGH |
| Improper scope validation | Request `read:own`, check if server grants `admin`/`write`/`read:all` | HIGH |
| Authorization code reuse | Same auth code submitted twice → RFC 6749 violation | HIGH |
| Open redirect abuse | Unregistered `redirect_uri` accepted → auth code theft | CRITICAL |

Also runs JWT algorithm checks on every user token provided:
- `alg=none` → **CRITICAL** (unsigned tokens accepted)
- `alg=HS256` → **MEDIUM** (symmetric algorithm, prefer RS256/ES256)

### 6. Forensic Logger
Every finding is saved as a timestamped JSON evidence file in `reports/evidence/`:

```
evidence_20240115_143022_BOLA_IDOR_A1B2C3D4.json
```

Each file contains:
- `metadata` — finding ID (UUID short), timestamp, tool version
- `vulnerability` — type, check name, severity, endpoint, parameter, resource ID
- `evidence` — payload used, HTTP status code, response body preview
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
Full-featured Click-based CLI with 11 options. See [Usage](#usage) section.

### 9. Mock Flask Server
Intentionally vulnerable Flask server for local testing with 7 vulnerable endpoints and 2 secure comparison endpoints.

---

## Project Structure

```
vigilant-api/
├── cli.py                        # Main entry point — run from here
├── requirements.txt              # Python dependencies
├── .gitignore                    # Excludes venv/, reports/, __pycache__
│
├── src/
│   ├── scanner.py                # Orchestrator — wires everything together
│   ├── spec_parser.py            # OpenAPI YAML/JSON parser
│   ├── auth.py                   # Auth handler + JWT inspection
│   ├── bola_detector.py          # BOLA/IDOR — 5 sub-checks
│   ├── ssrf_detector.py          # SSRF — 5 sub-checks
│   ├── oauth_detector.py         # OAuth flaws — 5 sub-checks
│   ├── logger.py                 # Forensic evidence file writer
│   └── reporter.py               # HTML + JSON report generator
│
├── mock_server/
│   └── app.py                    # Vulnerable Flask server (port 5000)
│
├── scripts/
│   └── refresh_dummyjson_tokens.py   # Fetch fresh tokens from dummyjson.com
│
└── sample_specs/
    ├── fintech.yaml              # OpenAPI 3.0.3 test spec for mock server (9 endpoints)
    ├── tokens.json               # Three mock server test tokens (alice, bob, admin)
    ├── dummyjson.yaml            # OpenAPI spec for dummyjson.com (real external API)
    └── dummyjson_tokens.json     # JWT tokens for dummyjson.com (expire after 60 min)
```

---

## Requirements

- Python 3.10+
- pip packages (see `requirements.txt`)

```
requests>=2.31.0
pyyaml>=6.0
jinja2>=3.1.2
flask>=3.0.0
click>=8.1.7
colorama>=0.4.6
PyJWT>=2.8.0
```

---

## Installation

```bash
git clone https://github.com/rootverdict/vigilant-api.git
cd vigilant-api
pip install -r requirements.txt
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

### All CLI options

```
Options:
  --spec           PATH     Path to OpenAPI YAML/JSON spec file        [required]
  --tokens         PATH     Path to JSON file with user tokens          [required]
  --ids            TEXT     Comma-separated resource IDs to probe       [default: 1,2,3,4,5]
  --output         DIR      Directory for report output                 [default: reports]
  --skip           TEXT     Skip check type: bola | ssrf | oauth        [repeatable]
  --callback       URL      Blind SSRF callback (Burp Collaborator/ngrok). Omit to skip blind SSRF.
  --oauth-config   PATH     JSON file with OAuth server config
  --delay          FLOAT    Seconds between requests (rate limiting)    [default: 0.0]
  --insecure               Disable TLS certificate verification
  --proxy          URL      HTTP proxy for all requests (e.g. Burp Suite)
  --verbose                Print every request URL and payload
```

### Common scan recipes

```bash
# Basic scan — all checks, default IDs
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json

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

# Skip OAuth checks (no OAuth server available)
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json --skip oauth

# BOLA only — skip everything else
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --skip ssrf --skip oauth

# Custom resource IDs and output directory
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --ids 1,2,3,10,50,99 --output my_pentest_reports

# Full scan with all options
python cli.py --spec sample_specs/fintech.yaml --tokens sample_specs/tokens.json \
  --delay 0.3 --proxy http://127.0.0.1:8080 \
  --callback https://YOUR_ID.burpcollaborator.net \
  --oauth-config oauth.json --verbose --output reports
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

At minimum two users are required for differential testing. The first user is treated as the resource owner; all others are tested as unauthorized accessors.

---

## OAuth Config File Format

Required only when using `--oauth-config`. Example `oauth.json`:

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
  Endpoints : 9
  Delay     : 0.0s  |  Verify TLS: True
  Proxy     : none
  Callback  : none (blind SSRF skipped)
============================================================

  GET     /transactions/{id}
    [HIGH] Simple IDOR
           Evidence → reports/evidence/evidence_..._A1B2.json
  POST    /transfer
    [HIGH] Body IDOR
           Evidence → reports/evidence/evidence_..._C3D4.json

============================================================
  Scan Complete — 3 finding(s)
  CRITICAL: 0  HIGH: 2  MEDIUM: 1  LOW: 0

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
  --delay 0.5 \
  --ids 1,2,3,4,5
```

`--skip ssrf` is recommended for external APIs you don't own — SSRF probes inject metadata URLs which are irrelevant to dummyjson and just add noise. `--delay 0.5` prevents rate-limiting.

### What to expect

- **JWT algorithm findings** — all three dummyjson tokens use `HS256` → 3 x MEDIUM findings
- **Simple IDOR findings** — dummyjson returns any user's data to any authenticated token → multiple HIGH findings across `/users/{id}`, `/posts/{id}`, `/carts/{id}`, `/todos/{id}`
- **Body IDOR / Mass Assignment** — DummyJSON echoes back PUT body fields, which will trigger findings
- **Estimated runtime** — 5-8 minutes with `--delay 0.5`

---

## Mock Server Endpoints

Run `python mock_server/app.py` to start a local vulnerable server on port 5000.

### Vulnerable endpoints

| Method | Path | Vulnerability | Check triggered |
|--------|------|--------------|----------------|
| GET | `/transactions/{id}` | No ownership check — any token reads any record | Simple IDOR |
| GET | `/profile/{user_id}` | No ownership check — leaks any user profile | Simple IDOR |
| GET | `/fetch?url=` | Fetches any URL without allowlist | Basic SSRF |
| POST | `/transfer` | Accepts any `from_account_id` without verifying ownership | Body IDOR |
| GET | `/export?id=` | Uses last `id` value when duplicated | Parameter Pollution |
| GET | `/resource/<ref>` | Decodes base64/hex/int ID with no ownership check | Indirect Reference |
| POST/PUT/PATCH | `/user/update` | Merges all request fields including privileged ones | Mass Assignment |

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
Scanner sends:   GET /authorize?response_type=code&client_id=X&redirect_uri=Y
                 (no state parameter)
Server responds: 302 Location: http://localhost/callback?code=AUTH_CODE
                                                             ↑
               Code returned without state = CSRF vulnerable (HIGH)
```

---

## Severity Levels

| Severity | Meaning | Example |
|----------|---------|---------|
| CRITICAL | Immediate compromise possible | SSRF reaching cloud metadata, `alg=none` JWT, OAuth open redirect |
| HIGH | Significant data exposure or privilege escalation | Simple IDOR, Body IDOR, Mass Assignment, Blind SSRF |
| MEDIUM | Limited impact or requires chaining | Parameter Pollution, Indirect Reference, HS256 JWT |
| LOW | Informational / minor issues | — |

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
| OAuth — Missing state | Require cryptographically random `state` on every authorization request |
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
- UUID-style path params not automatically detected for BOLA (only params containing "id")
- OAuth checks require a reachable authorization server
- Blind SSRF confirmation requires an external out-of-band listener (Burp Collaborator, ngrok, interactsh)
- No built-in support for multi-step flows or stateful test sequences
- Rate limiting is uniform (same delay for all requests); no adaptive throttling

---

## License

MIT

---

*Vigilant-API v1.0 · rootverdict · 32-Week AppSec Roadmap*
