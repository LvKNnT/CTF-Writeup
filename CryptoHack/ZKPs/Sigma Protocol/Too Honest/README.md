# Too Honest Writeup

## Summary

Too Honest is a Girault-style identification challenge over an RSA group. The prover accepts an oversized verifier challenge and computes `z = r + e*w` over the integers, so choosing `e` larger than the nonce bound lets the solver recover `w` with integer division.

Flag:

```text
crypto{2_hon3st_to_b3_tru3}
```

## Triage

The prover samples `r < 2^768` and does not reduce the response modulo the hidden RSA group order. It also does not enforce the intended challenge bound.

## Solve Path

Send a huge challenge:

```python
e = 2 ** 800
```

The response has the form:

```text
z = e*flag + r
0 <= r < e
```

so the witness is simply:

```python
flag = z // e
r = z - e * flag
```

The solver verifies `y * g^flag = 1 mod N` and `a = g^r mod N`, then strips random padding after `}`.

## Exploit

Run:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13429`, sends the oversized challenge, extracts the flag integer, and prints the decoded flag.

## Verification

Verified live against `socket.cryptohack.org:13429` from WSL using the `sage` conda environment:

```text
crypto{2_hon3st_to_b3_tru3}
```

## Flag

```text
crypto{2_hon3st_to_b3_tru3}
```

## Lessons Learned

- Protocol challenge ranges must be enforced.
- Integer arithmetic without modular reduction can expose secret witnesses.
- If `e` is bigger than the blinding nonce range, `z // e` reveals the secret.
