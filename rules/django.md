# Rules: Django

Load when Django detected.

## settings.py hygiene

- `DEBUG = True` in production wiring (check how settings load: env-based
  split settings vs single file).
- `ALLOWED_HOSTS` with wildcard; `CSRF_MIDDLEWARE` removed;
  `SECURE_*` flags unset (SSL redirect, HSTS, cookie flags);
  `SESSION_COOKIE_*`/`CSRF_COOKIE_*` flags.
- `SECRET_KEY` hardcoded or committed; default `INSTALLED_APPS` debug panels.

## ORM & raw queries

- `extra()`/`raw()`/`cursor.execute` with interpolation — the ORM's
  parameterization does not apply to string-built SQL; `%s` placeholders in
  raw SQL are the only safe form.
- `order_by` with user-controlled column names (usually safe; check
  `Meta.base_manager` / raw fragments).
- `Q` objects built from user dicts (field-name injection into lookups:
  `user__password` lookups via client-controlled keys in `filter(**kwargs)`).

## Templates

- Autoescape is on by default — findings only where it's disabled:
  `mark_safe()` on user content, `|safe` filter on user fields,
  `autoescape off` blocks, custom template engines with autoescape off.

## Admin

- `/admin` reachable (URLs.py includes) — check: staff-only enforcement is
  built-in, but weak-password/credential-stuffing exposure, `AdminConfig`
  with default title, custom admin views missing `@staff_member_required`.
- Django admin with `DEBUG=False` still exposes login — brute-force
  protection is absent by default (rate limit presence is the check).

## DRF (if djangorestframework)

- Serializers: `fields = '__all__'` on write serializers (mass assignment);
  `ModelViewSet` without `permission_classes` (default may be
  `AllowNone`/`IsAuthenticated` depending on settings — check
  `DEFAULT_PERMISSION_CLASSES`; empty settings = AllowAny).
- Object-level permissions: `check_object_permissions` present in
  `get_queryset` overrides or not; filtered querysets leaking other users'
  rows when `get_queryset` doesn't scope by `request.user`.

## Typical Django findings

| Pattern | Risk |
|---|---|
| `cursor.execute(f"SELECT ... {req.GET['q']}")` | SQLi |
| `redirect(request.GET['next'])` without url validation | open redirect |
| `FileResponse(open(settings.MEDIA_ROOT + name))` | path traversal |
| `serializers.ModelSerializer` `fields = '__all__'` on User | mass assignment of `is_staff` |
| `SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'` | session data client-readable |
