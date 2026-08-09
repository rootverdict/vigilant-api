# Configuration and Usage

This guide covers authentication files, OAuth settings, scan recipes, output,
CI behavior, and common problems. For a first local scan, start with the
[README quick start](../README.md#quick-start).

## Token file

Pass a JSON array to `--tokens`. Each entry represents an identity the scanner
can use for differential authorization testing.

### Bearer tokens

```json
[
  {
    "name": "alice",
    "token": "token_alice",
    "user_id": 1,
    "resource_ids": [1, 4]
  },
  {
    "name": "bob",
    "token": "token_bob",
    "user_id": 2,
    "resource_ids": [2, 5]
  },
  {
    "name": "admin",
    "token": "token_admin",
    "user_id": 9,
    "role": "admin",
    "owns_all": true
  }
]
```

At least two non-privileged identities are recommended for BOLA testing.
Privileged entries marked with `"role": "admin"` or `"owns_all": true` are not
used as unauthorized attackers.

### API keys

The key name and location come from the operation's OpenAPI security scheme:

```json
[
  {
    "name": "service-a",
    "scheme": "apiKey",
    "key": "secret-a",
    "user_id": 1
  },
  {
    "name": "service-b",
    "scheme": "apiKey",
    "key": "secret-b",
    "user_id": 2
  }
]
```

For multiple named API-key schemes:

```json
[
  {
    "name": "service-a",
    "scheme": "apiKey",
    "api_keys": {
      "HeaderKey": "header-secret",
      "QueryKey": "query-secret"
    }
  }
]
```

OpenAPI security requirements are honored as written: schemes in one security
requirement object are combined with AND, while separate objects are treated as
OR alternatives.

### OAuth identities

An OAuth entry can supply an `access_token` directly, or credentials from which
the scanner can obtain one:

```json
[
  {
    "name": "alice",
    "scheme": "oauth2",
    "access_token": "eyJ...",
    "refresh_token": "refresh-value",
    "token_url": "https://auth.example.com/oauth/token",
    "client_id": "scanner-client",
    "client_secret": "client-secret",
    "user_id": 1
  }
]
```

Password and client-credentials grants are also supported when the required
credentials are present. Tokens are refreshed automatically when a refresh
token and client details are available.

Do not commit real tokens or client secrets. Keep local credential files outside
version control and rotate anything that is accidentally exposed.

## OAuth detector config

`--oauth-config` enables OAuth logic checks. The file must contain a JSON object.
The bundled mock-server configuration is ready to use:

```json
{
  "auth_url": "http://localhost:5000/oauth/authorize",
  "token_url": "http://localhost:5000/oauth/token",
  "client_id": "vigilant-test-client",
  "client_secret": "vigilant-test-secret",
  "redirect_uri": "http://localhost:5000/callback"
}
```

For another authorization server:

```json
{
  "auth_url": "https://auth.example.com/oauth/authorize",
  "token_url": "https://auth.example.com/oauth/token",
  "client_id": "your-client-id",
  "client_secret": "your-client-secret",
  "redirect_uri": "http://localhost/callback"
}
```

### Optional keys

| Key | Purpose |
|---|---|
| `auth_code` | A real, freshly-issued authorization code. When present, the code-reuse check exchanges *this* code twice against a live server instead of a synthetic one — turning it from a mock-only check into a genuine test. Capture it from a browser login, then run the scan promptly (codes are short-lived and single-use). |

The token-leakage check needs no extra config: it probes the real implicit grant
(`response_type=token`) against `auth_url` and flags any access token returned in
the redirect URL.

## Scan recipes

All examples use the source checkout. If installed with `pip install -e .`,
replace `python cli.py` with `vigilant-api`.

### Full active scan of the local mock server

```bash
python cli.py \
  --spec sample_specs/fintech.yaml \
  --tokens sample_specs/tokens.json \
  --oauth-config sample_specs/oauth_config.json \
  --active
```

### Run one detector family

```bash
# BOLA only
python cli.py --spec api.yaml --tokens tokens.json --skip ssrf --skip oauth

# SSRF only
python cli.py --spec api.yaml --tokens tokens.json --skip bola --skip oauth

# OAuth only
python cli.py --spec api.yaml --tokens tokens.json \
  --skip bola --skip ssrf --oauth-config oauth.json
```

JWT inspection is independent of OAuth checks. Add `--skip jwt` when it should
also be disabled.

### Rate limit and cap requests

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --delay 0.5 --max-requests 250
```

### Route traffic through an intercepting proxy

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --proxy http://127.0.0.1:8080 --verbose
```

For a self-signed target, add `--insecure`. This disables certificate
verification and should not be the default.

### Blind SSRF callback

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --callback https://YOUR-ID.example-callback.test
```

An in-band reflection is not proof of an outbound request. Confirm the
interaction in the callback service.

### Custom resources and output

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --ids 1,2,3,10,50,99 --output my-reports
```

## Output

The output directory contains:

```text
reports/
├── report.json
├── report.html
└── evidence/
    └── evidence_<timestamp>_<type>_<id>.json
```

- `report.json` contains scan metadata, severity totals, and complete findings.
- `report.html` is a human-readable report.
- `evidence/` contains one forensic JSON record per finding, including request,
  response preview, payload, description, remediation, and a reproduction hint.

The process exits with status `1` when at least one CRITICAL or HIGH finding is
reported, `0` when neither is present, and `2` when the scan itself fails.

### GitHub Actions

```yaml
- name: API security scan
  run: python cli.py --spec api-spec.yaml --tokens tokens.json
```

Store credentials in your CI secret manager and construct the token file during
the job. Do not commit production credentials.

## External smoke test with DummyJSON

DummyJSON can be used to verify the end-to-end scanner flow. It is a third-party
service, so review its current terms and test conservatively.

```bash
python scripts/refresh_dummyjson_tokens.py

python cli.py \
  --spec sample_specs/dummyjson.yaml \
  --tokens sample_specs/dummyjson_tokens.json \
  --skip ssrf \
  --delay 0.5 \
  --ids 1,2,3
```

`sample_specs/dummyjson_tokens.json` is generated, not tracked — the repository
ships `dummyjson_tokens.json.example` as its shape. The refresh script writes real
access tokens there, so it is deliberately git-ignored; never commit the generated
file.

The generated tokens expire. Refresh them immediately before the scan. SSRF is
skipped because metadata probes add noise and are inappropriate for this smoke
test.

## Troubleshooting

### The scanner reports that a file is missing

Paths are resolved from the current working directory. Run commands from the
repository root or pass absolute paths.

### BOLA checks produce no findings

Confirm that:

- The OpenAPI document declares ID-like path or query parameters.
- At least two non-privileged identities are present.
- `user_id`, `resource_ids`, or ownership fields in responses establish who
  owns each resource.
- The supplied IDs exist.

The scanner deliberately avoids a Simple IDOR verdict when it cannot establish
ownership.

### Active checks are not running

Safe mode is the default. Add `--active` only for an authorized target where
creating or modifying data is acceptable.

### Blind SSRF is skipped

Supply `--callback`. Even then, verify the callback service directly because a
negative in-band result does not exclude an outbound interaction.

### OAuth checks are skipped or incomplete

Supply `--oauth-config` and confirm both OAuth endpoints are reachable. The
authorization-code-reuse probe uses a synthetic code unless `auth_code` is
supplied, and that fallback is only meaningful against the bundled mock server.
The scope and code-reuse probes additionally require `--active`, because they
request and consume tokens.

### The request budget is exhausted

Reduce `--ids`, skip detector families that are out of scope, or increase
`--max-requests` after confirming the larger request volume is acceptable.

