# Hunter: File & Storage

## Mission

Find where the app moves bytes to/from the filesystem or object storage on
behalf of users, and whether a user can move someone else's bytes, or bytes
to somewhere dangerous.

## Where to hunt

- Upload handlers: multer/busboy/formidable, DRF FileField, FastAPI UploadFile, presigned-URL issuance.
- Download/send-file routes: `res.sendFile`, `send_file`, `FileResponse`, static-serving config.
- Path composition: `path.join`/`os.path.join`/string concat with user-controlled segments.
- Object-storage clients: S3/GCS/Azure operations, bucket/prefix/key composition, ACL/presign calls.
- Import/export features: zip extraction, CSV/XML import, avatar/attachment processing.

## Checklist

- [ ] Path traversal: `..`, encoded `..%2f`, absolute-path acceptance in upload *destination* or download *source*; `path.join(base, userInput)` where userInput can be absolute or `..`.
- [ ] Arbitrary file write: destination not restricted to a dedicated upload dir; user-controlled filename used verbatim (`../../etc/cron.d/x`, `../.env` overwrite).
- [ ] Arbitrary file read: user-controlled path in `sendFile`/`open`/`FileResponse` without base-dir jail and canonicalization check.
- [ ] Upload validation: extension-only or content-type-only checks; MIME sniffing absent; executable/scriptable extensions allowed in web-served dirs (.php, .html, .svg, .exe).
- [ ] MIME spoofing: magic-byte validation absent while serving user uploads back with user-controlled content type.
- [ ] Executable uploads: uploads landing in webroot or served from the app domain (stored XSS via SVG/HTML, RCE via .php).
- [ ] Public object storage: bucket ACLs public; listing enabled; keys guessable/enumerable (sequential names, user IDs without signed URLs).
- [ ] Signed URL misuse: overly long expiry (days), no content-type/size constraints in the policy, signing server accepts arbitrary keys/paths, unsigned metadata endpoints leaking objects.
- [ ] Unauthorized object access: download route loads by object ID without ownership check (cross-check authorization — file here when the storage layer is the boundary).
- [ ] Filename manipulation: control chars, unicode tricks (RTL overrides), null bytes, absurd lengths breaking downstream processing.

## Evidence requirements

Cite the file:line composing the path/key, the file:line performing the IO,
and the validation present/absent. State the serving context for executable
uploads (webroot vs private store + authenticated proxy).

## False-positive traps

- `path.basename()`/`sanitize-filename` applied before composition.
- Storage keys generated server-side (UUID) with user filename stored as metadata only.
- Uploads to private bucket + short-lived presigned GETs for serving.
- Framework static servers with documented traversal protections (verify version).

## Output

Candidates per schema, category `file-storage`.
