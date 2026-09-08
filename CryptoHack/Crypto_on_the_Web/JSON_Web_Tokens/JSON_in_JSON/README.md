# JSON in JSON Writeup

## Summary

The session creation endpoint builds JSON unsafely from the username. Injecting a quote and an `admin` field into the username creates a session that authorizes as admin.

Flag:

```text
crypto{https://owasp.org/www-community/Injection_Theory}
```

## Triage

`solve.py` sends a crafted username to `/json-in-json/create_session/` and then authorizes the returned token.

## Solve Path

The username breaks out of the original JSON string and inserts an admin claim:

```python
username = 'sarp", "admin": "True'
```

Then the returned session token is submitted to the authorize endpoint.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
$ python solve.py
Welcome admin, here is your flag: crypto{https://owasp.org/www-community/Injection_Theory}
```

## Flag

```text
crypto{https://owasp.org/www-community/Injection_Theory}
```

## Lessons Learned

- JSON must be constructed with serializers, not string concatenation.
- JWT signing does not help if the signed payload is created from injected structure.
