# Hunter: Cryptography

## Mission

Find crypto that is weak, misused, or homemade. The standard: standard
libraries, standard constructions, standard parameters — anything else is a
candidate.

## Where to hunt

- Hashing: password storage (`md5`, `sha1`, plain `sha256` without salt/KDF), token derivation.
- Encryption: `crypto.createCipheriv` usage (mode, IV, key derivation), `AES-ECB`, static IVs, `DES/RC4`, `AES-CBC` without MAC.
- Randomness: `Math.random()` for security values, `random.randint` for tokens, session/reset/API key generation, JWT secrets.
- Signatures: verification that doesn't pin the algorithm, `verify()` with attacker-controlled algorithm/keys, JWT `alg` handling.
- Keys: hardcoded keys/IVs/salts/peppers in code or config, keys derived from names/environments.
- TLS: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `verify=False` (requests/urllib3), disabled cert checks in clients, plain-HTTP for credentials.

## Checklist

- [ ] Weak algorithms: MD5/SHA1 for passwords or signatures, DES/3DES/RC4, ECB mode.
- [ ] Insecure password hashing: unsalted or fast hashes (sha256/md5) for credentials; missing bcrypt/argon2/scrypt/PBKDF2 parameters review (work factor).
- [ ] Hardcoded keys: encryption/signing keys, IVs, salts, API signing secrets in source/config (cross-check secrets; file here when the *use* is the flaw).
- [ ] Predictable randomness: `Math.random()`/`rand` for tokens, OTPs, reset links, session IDs, coupon codes.
- [ ] Incorrect encryption usage: AES-CBC without authentication (padding oracles), nonce reuse in CTR/GCM, IV derived deterministically from plaintext-adjacent data, key reuse across purposes.
- [ ] Broken signature verification: accepting multiple algorithms (`"alg"` not pinned), verifying HMAC with public-key logic, signature checked but result ignored.
- [ ] Insecure token generation: tokens shorter than claimed entropy, derived from user-known data (`md5(userId + timestamp)`).
- [ ] TLS misconfiguration: verification disabled, `http://` for auth flows, cipher allowlists with legacy entries in server config.

## Evidence requirements

Cite the exact call site file:line, the construction used, and the security
purpose (what asset it protects). For randomness, cite the value's purpose and
the predictability argument.

## False-positive traps

- Non-security uses of weak primitives (cache keys, content hashes, ETags).
- `Math.random()` for non-adversarial identifiers (only file when predictability grants access).
- Verified TLS libraries with sane defaults; local/dev-only config gated by environment.
- Timing-safe comparison present (`crypto.timingSafeEqual`, `hmac.compare_digest`).

## Output

Candidates per schema, category `cryptography`.
