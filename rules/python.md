# Rules: Python

Load when python detected. Complements framework-specific files (django.md)
and the injection/authentication playbooks with Python-context knowledge.

## Sinks

- `eval`/`exec`/`compile` with any request-derived string.
- `pickle.loads` on request data/cookies/cache — RCE by design; also
  `yaml.load` (use `safe_load`), `marshal`.
- `os.system`, `subprocess.*` with `shell=True` or string commands; argument
  injection on `shell=False` calls with user-controlled elements.
- SQL: f-strings/`.format()`/`%`/`+` into `cursor.execute`, SQLAlchemy
  `text()` with formatted SQL, `order_by(text(...))`, raw `session.execute`
  with concatenation.
- SSTI: `render_template_string(user)`, Jinja `Template(user).render()`,
  environment with `autoescape=False`.
- Path: `open(user)`, `send_file(user)`, `os.path.join(base, user)` with
  absolute user paths (join discards base), `..` unfiltered.
- SSRF: `requests.get(user_url)` without scheme/host allowlist; cloud
  metadata reachability elevates.

## Request handling

- Flask: `debug=True`, secret key hardcoded/weak (`app.secret_key = 'x'`),
  session cookie signing with it; `send_file`/`send_from_directory` path args.
- FastAPI: pydantic models actually used per route (vs `Request.json()` raw);
  `UploadFile` handling (extension validation only?); dependency-injected
  auth (`Depends`) present per route or globally absent.
- Global exception handlers returning `str(e)`/tracebacks.
- Deserialization of JWT/session tokens with `verify=False` equivalents
  (`options={"verify_signature": False}` in python-jose).

## Crypto quick-table

| Pattern | Risk |
|---|---|
| `hashlib.md5(pw)` | weak password hash |
| `random.randint` for OTP/tokens | predictable tokens |
| `jwt.encode(payload, key, algorithm='none')` | forgeable tokens |
| `requests.get(url, verify=False)` | TLS bypass |
| `Cipher(` (pycryptodome) with ECB | weak mode |

## Coverage

Record: route count per framework, pydantic/schema coverage, raw-query count,
`eval`/`exec`/`pickle` occurrences with reachability verdicts.
