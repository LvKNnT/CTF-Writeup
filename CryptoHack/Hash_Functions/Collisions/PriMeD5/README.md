# PriMeD5 Writeup

## Summary

The service signs MD5 hashes of prime numbers. A chosen MD5 collision where one integer is prime and the paired integer is not lets us reuse a valid signature on a forbidden value and leak the flag.

Flag:

```text
crypto{MD5_5uck5_p4rt_tw0}
```

## Triage

`gen.py` shows the MD5-colliding byte strings and appends bytes until one interpreted integer is prime while the other is composite. `solve.py` signs the prime `x` and verifies the signature against `y`.

## Solve Path

The important property is:

```text
MD5(long_to_bytes(x)) == MD5(long_to_bytes(y))
```

The server signs `x` because it is prime. The signature verifies for `y` because RSA-PKCS#1 verification is performed over the MD5 digest only.

## Exploit

Run:

```bash
python solve.py
```

## Verification

```text
{"msg": "Valid signature. First byte of flag: crypto{MD5_5uck5_p4rt_tw0}"}
```

## Flag

```text
crypto{MD5_5uck5_p4rt_tw0}
```

## Lessons Learned

- Signatures inherit the collision resistance of the hash they sign.
- MD5 should not be used in signature schemes.
