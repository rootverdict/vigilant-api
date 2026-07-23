# Detector Reference

Vigilant-API performs black-box security testing against REST APIs described by
an OpenAPI 3.x document. This reference explains what each detector sends, what
counts as evidence, and how findings are rated.

Only scan systems you own or are explicitly authorized to test. Active checks
can create or modify data.

## BOLA / IDOR

The BOLA detector uses multiple authenticated identities and resource IDs to
look for missing object-level authorization.

| Check | Technique | Severity |
|---|---|---|
| Simple IDOR | A non-owner requests a resource that belongs to another user | HIGH |
| Parameter pollution | Sends an ID-like query parameter twice in both orderings | MEDIUM |
| Body IDOR | Places another user's ID in POST/PUT request fields | HIGH |
| Indirect reference | Tries predictable encodings of a resource ID | MEDIUM |
| Mass assignment | Submits privileged fields and checks whether they are accepted | MEDIUM |

### Simple IDOR

The scanner first establishes an ownership baseline, then compares the same
resource when requested by a different user:

```text
alice -> GET /transactions/1 -> 200 {"id": 1, "owner_id": 1, "amount": 500}
bob   -> GET /transactions/1 -> 200 {"id": 1, "owner_id": 1, "amount": 500}
```

Returning materially similar owner data to the non-owner produces a HIGH
finding. Ownership is inferred from response fields such as `owner_id` and
`user_id`, or declared through `resource_ids` in the token file. If ownership
cannot be established, the scanner skips this verdict instead of guessing.

### Parameter pollution

For declared ID-like query parameters, the scanner sends both:

```text
?account_id=victim_id&account_id=attacker_id
?account_id=attacker_id&account_id=victim_id
```

This detects servers or intermediaries that disagree about whether the first or
last value should be trusted. Required path parameters on the same operation
are populated from OpenAPI examples or defaults.

### Body IDOR

In active mode, POST and PUT requests are tested with another user's ID in
common identity fields, including snake_case and camelCase forms such as
`user_id`, `account_id`, `owner_id`, `customer_id`, `resource_id`, `userId`,
`accountId`, and `ownerId`.

### Indirect reference enumeration

The scanner tries four predictable encodings:

| Encoding | Example for ID `1` |
|---|---|
| Base64 | `MQ==` |
| URL-safe Base64 | `MQ` |
| Zero-padded hexadecimal | `00000001` |
| MD5 | `c4ca4238a0b923820dcc509a6f75849b` |

Authorization must be enforced regardless of how an object reference is
represented.

### Mass assignment

In active mode, POST, PUT, and PATCH bodies are tested with privileged fields:

| Category | Example fields |
|---|---|
| Role escalation | `role`, `is_admin`, `admin`, `permissions`, `scope` |
| Financial | `balance`, `credit`, `credits` |
| Verification bypass | `verified`, `email_verified`, `is_verified` |
| Tier escalation | `subscription`, `account_type`, `plan` |

A MEDIUM finding means the response reflected the submitted value. Persistence
is not verified, so confirm the result manually before escalating its severity.

## SSRF

The SSRF detector targets OpenAPI parameters whose names suggest a URL or
destination, including `url`, `uri`, `endpoint`, `redirect`, `callback`,
`next`, `src`, `dest`, `target`, `webhook`, `proxy`, and `host`. Query, path,
header, and cookie parameters are supported.

| Check | Technique | Severity |
|---|---|---|
| Basic SSRF | Injects cloud metadata URLs and looks for metadata signatures | CRITICAL |
| Blind SSRF | Injects a supplied callback URL | LOW until confirmed out-of-band |
| Redirect/filter bypass | Uses alternate IP and authority representations | CRITICAL |
| Protocol smuggling | Tries non-HTTP schemes and requires protocol-specific evidence | CRITICAL |
| Partial SSRF | Exercises encoding and URL parser edge cases | HIGH |

### Basic SSRF

The scanner injects AWS, GCP, and Azure metadata endpoints. A finding requires
response evidence such as AWS credential keys, AMI identifiers, cloud-provider
metadata markers, or a raw metadata IP address.

### Blind SSRF

Blind checks run only when `--callback` is supplied. An in-band reflection is a
weak signal and remains LOW severity. Confirm a DNS or HTTP interaction in your
out-of-band service before treating the issue as HIGH or CRITICAL. A negative
scan result does not rule out blind SSRF.

### Redirect and filter bypass

Payloads include alternative representations such as:

- `169.254.169.254.nip.io`
- `[::ffff:169.254.169.254]`
- `0.0.0.0`
- `localhost@169.254.169.254`

### Protocol smuggling

Schemes include `file://`, `dict://`, `gopher://`, and `ftp://`. Generic
reflections do not count as proof; the response must contain a relevant
signature such as a passwd record, Memcached response, Redis response, or FTP
banner.

### Partial SSRF

The scanner tests authority, fragment, and encoded-tab tricks such as
`169.254.169.254@trusted.com`, `trusted.com#@169.254.169.254`, and
`169.254.169.254%09`.

## OAuth 2.0

OAuth checks require `--oauth-config`.

| Check | What it tests | Severity |
|---|---|---|
| State integrity | Supplied `state` is missing or changed | HIGH |
| Token leakage in URL | An access token appears in a redirect URL | HIGH |
| Scope validation | Returned scope is broader than requested | HIGH |
| Authorization code reuse | The same code can be exchanged twice | HIGH |
| Open redirect | An unregistered `redirect_uri` is accepted | CRITICAL |

The token-leakage and code-reuse checks use synthetic flows designed for the
bundled mock server. A negative result against a real OAuth provider does not
prove those properties are secure; full testing requires capturing a live
browser authorization flow.

## JWT algorithm inspection

Every supplied JWT is inspected unless `--skip jwt` is used:

| Result | Severity | Meaning |
|---|---|---|
| `alg=none` | CRITICAL | Unsigned token |
| `alg=HS256` | INFO | Valid algorithm; informational architecture note |

An HS256 finding is not a confirmed vulnerability. Prefer asymmetric signing
such as RS256 or ES256 for multi-service architectures, or protect HS256 with a
strong, randomly generated secret.

## Severity model

| Severity | Meaning | Example |
|---|---|---|
| CRITICAL | Immediate compromise may be possible | Cloud metadata SSRF, OAuth open redirect |
| HIGH | Significant exposure or privilege escalation | Simple IDOR, body IDOR |
| MEDIUM | Limited impact or chaining/manual confirmation needed | Parameter pollution, reflected mass assignment |
| LOW | Unconfirmed signal | Blind SSRF reflection |
| INFO | Informational observation | HS256 JWT |

## Remediation summary

| Vulnerability | Recommended control |
|---|---|
| BOLA / IDOR | Check the authenticated subject against resource ownership on every request |
| Parameter pollution | Reject duplicate security-sensitive parameters |
| Body IDOR | Derive the acting subject from authentication, not request fields |
| Indirect reference | Use unpredictable IDs and enforce authorization independently |
| Mass assignment | Bind requests through an allowlisted DTO or schema |
| SSRF | Allowlist destinations and block private, loopback, link-local, and metadata ranges |
| Protocol smuggling | Allow only HTTP(S) schemes and disable unnecessary redirects |
| OAuth state | Return and validate the exact client-generated state value |
| Token leakage | Use authorization code flow with PKCE; never place tokens in URLs |
| Scope bypass | Never grant broader scopes than the client and user authorized |
| Code reuse | Invalidate authorization codes after their first exchange |
| Open redirect | Match redirect URIs against an exact preregistered allowlist |
| JWT `alg=none` | Enforce an explicit signing-algorithm allowlist |
