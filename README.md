# Vigilant-API

Vigilant-API is a black-box API security scanner for REST APIs. It reads an
OpenAPI 3.x specification, authenticates as multiple users, and tests for
logic-layer vulnerabilities that conventional payload scanners often miss.

It currently detects:

- BOLA / IDOR authorization failures
- Server-Side Request Forgery (SSRF)
- OAuth 2.0 implementation flaws
- Weak or unsafe JWT algorithm choices

Each finding is recorded as forensic JSON evidence. A scan also produces
machine-readable JSON and human-readable HTML reports.

> [!WARNING]
> Use Vigilant-API only against systems you own or are explicitly authorized to
> test. Active mode can create, update, or delete target data.

## Features

| Area | Capabilities |
|---|---|
| OpenAPI | YAML/JSON parsing, server variables, parameters, request bodies, security schemes, local `$ref` files |
| Authentication | Bearer tokens, API keys, OAuth tokens, token refresh, password and client-credentials grants |
| BOLA / IDOR | Differential access, parameter pollution, body IDOR, indirect references, mass assignment |
| SSRF | Cloud metadata probes, filter bypasses, blind callbacks, non-HTTP protocols |
| OAuth | State integrity, token leakage, scope validation, code reuse, open redirects |
| Safety | Read-only default, explicit active mode, rate limiting, hard request budget |
| Reporting | Per-finding evidence plus JSON and HTML summaries |
| Integrations | Exit codes for CI/CD and optional intercepting-proxy support |

See [Detector Reference](docs/DETECTORS.md) for detection logic, evidence
requirements, severity, and remediation guidance.

## Requirements

- Python 3.10 or newer
- An OpenAPI 3.x YAML or JSON specification
- Credentials for at least two test identities for differential BOLA testing

## Installation

Clone the repository and install the runtime dependencies:

```bash
git clone https://github.com/rootverdict/vigilant-api.git
cd vigilant-api
python -m pip install -r requirements.txt
```

Alternatively, install the project in editable mode to expose the
`vigilant-api` command:

```bash
python -m pip install -e .
```

For development:

```bash
python -m pip install -e ".[dev]"
```

## Quick start

The repository includes an intentionally vulnerable Flask server and matching
OpenAPI and credential files.

### 1. Start the mock server

```bash
python mock_server/app.py
```

The server listens on `http://localhost:5000`.

### 2. Run a safe scan

In a second terminal:

```bash
python cli.py \
  --spec sample_specs/fintech.yaml \
  --tokens sample_specs/tokens.json
```

Safe mode is the default. It limits probing to read-only HTTP methods.

### 3. Run the complete local test

The bundled mock server is designed for active testing:

```bash
python cli.py \
  --spec sample_specs/fintech.yaml \
  --tokens sample_specs/tokens.json \
  --oauth-config sample_specs/oauth_config.json \
  --active
```

Use `--active` only when modifying the target's data is authorized and
acceptable.

If the package is installed in editable mode, `vigilant-api` can replace
`python cli.py` in these commands.

## Authentication input

Pass a JSON array of test identities to `--tokens`. A minimal bearer-token file
looks like this:

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
  }
]
```

`resource_ids` is optional but improves ownership attribution. The scanner can
also infer ownership from response fields such as `owner_id` and `user_id`. It
skips high-confidence Simple IDOR verdicts when ownership cannot be established.

API-key and OAuth credential formats are documented in
[Configuration and Usage](docs/CONFIGURATION.md#token-file).

Never commit production tokens, API keys, refresh tokens, or client secrets.

## Common commands

### Select detector families

```bash
# BOLA only
python cli.py --spec api.yaml --tokens tokens.json \
  --skip ssrf --skip oauth

# SSRF only
python cli.py --spec api.yaml --tokens tokens.json \
  --skip bola --skip oauth

# OAuth only
python cli.py --spec api.yaml --tokens tokens.json \
  --skip bola --skip ssrf --oauth-config oauth.json
```

### Rate-limit and cap a scan

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --delay 0.5 --max-requests 250
```

### Inspect traffic through a proxy

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --proxy http://127.0.0.1:8080 --verbose
```

### Enable blind SSRF checks

```bash
python cli.py --spec api.yaml --tokens tokens.json \
  --callback https://YOUR-ID.example-callback.test
```

An in-band signal is not proof of blind SSRF. Confirm the interaction in the
out-of-band callback service.

More examples are available in
[Configuration and Usage](docs/CONFIGURATION.md#scan-recipes).

## CLI options

| Option | Description | Default |
|---|---|---|
| `--spec PATH` | OpenAPI YAML/JSON file | Required |
| `--tokens PATH` | JSON file containing test identities | Required |
| `--ids TEXT` | Comma-separated resource IDs | `1,2,3,4,5` |
| `--output DIR` | Report output directory | `reports` |
| `--skip TYPE` | Skip `bola`, `ssrf`, `oauth`, or `jwt`; repeatable | None |
| `--callback URL` | Blind SSRF callback URL | Blind checks disabled |
| `--oauth-config PATH` | OAuth detector configuration | OAuth checks disabled |
| `--delay FLOAT` | Seconds between requests | `0.0` |
| `--proxy URL` | Proxy for outbound requests | None |
| `--insecure` | Disable TLS certificate verification | Off |
| `--verbose` | Print each request and payload | Off |
| `--active` | Enable write-method probes | Off |
| `--max-requests INT` | Hard request cap | `1000` |
| `--version`, `-V` | Print the version | |

## Output

By default, scan artifacts are written to:

```text
reports/
├── report.json
├── report.html
└── evidence/
    └── evidence_<timestamp>_<type>_<id>.json
```

- `report.json` is intended for automation and CI/CD.
- `report.html` provides an executive summary and finding details.
- `evidence/` contains individual request, response, payload, and remediation
  records for manual validation.

The CLI exits with:

| Code | Meaning |
|---|---|
| `0` | No CRITICAL or HIGH findings |
| `1` | At least one CRITICAL or HIGH finding |
| `2` | The scan failed to complete |

Example CI step:

```yaml
- name: API security scan
  run: python cli.py --spec api-spec.yaml --tokens tokens.json
```

## Limitations

- REST/OpenAPI only; GraphQL and gRPC are not supported.
- Remote HTTP `$ref` documents are not downloaded. Local external files are
  supported.
- Detection depends on parameters and request bodies declared in the OpenAPI
  specification.
- Active body checks require `--active`.
- Blind SSRF requires out-of-band confirmation.
- Two OAuth probes are tailored to the bundled mock server and do not replace a
  real browser authorization flow.
- Multi-step stateful workflows are not supported.
- Rate limiting uses one uniform delay for all requests.

## Documentation

- [Detector Reference](docs/DETECTORS.md) — checks, evidence, severity, and remediation
- [Configuration and Usage](docs/CONFIGURATION.md) — authentication, OAuth, recipes, CI, and troubleshooting
- [Development Guide](docs/DEVELOPMENT.md) — architecture, tests, mock endpoints, and extensions

## Development

Install the development dependencies, then run:

```bash
ruff check .
mypy
pytest --cov=src --cov-report=term-missing
```

CI tests Python 3.10 and 3.12 and requires at least 70% coverage. See the
[Development Guide](docs/DEVELOPMENT.md) for the project structure and extension
points.

## License

[MIT](./LICENSE)
