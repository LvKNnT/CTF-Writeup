# Bruce Schneier's Password Writeup

## Summary

This challenge checks whether a password has ASCII word characters, includes uppercase/lowercase/digits, and has both an ASCII sum and an overflowed NumPy `int64` product that are prime. The solve searches controlled counts of odd characters until both arithmetic predicates are satisfied.

Flag:

```text
crypto{https://www.schneierfacts.com/facts/1341}
```

## Triage

The challenge uses NumPy-style integer arithmetic, so `array.prod()` can overflow signed 64-bit range. Even character codes would force the product to be even, so the solve restricts itself to odd ASCII values.

## Solve Path

The solver models signed 64-bit overflow:

```python
x = (x * ord(c)) % 2**64
if x >= 2**63:
    x -= 2**64
```

It searches passwords made of `A`, `a`, and `1`, ensuring the shape requirements are met while testing primality of both the sum and the overflowed product. Once it finds a password, it can submit:

```json
{"password": "<found password>"}
```

## Exploit

The standalone exploit is `Misc/Password Complexity/Bruce Schneier's Password/solve.sage`.

```bash
sage solve.sage --host socket.cryptohack.org --port 13400
```

## Verification

Verified the offline password search in WSL using the `sage` conda environment:

```text
password = Aa1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111
sum      = 9619
product  = 9196430423196744401
attempts = 193
payload  = {"password": "Aa1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"}
response = {"msg": "crypto{https://www.schneierfacts.com/facts/1341}"}
```

## Flag

```text
crypto{https://www.schneierfacts.com/facts/1341}
```

## Lessons Learned

- Numeric overflow can turn impossible-looking primality constraints into searchable ones.
- Matching the target language/library integer semantics is part of the cryptanalysis.
- Restricting the alphabet can preserve required classes while reducing the search space.
