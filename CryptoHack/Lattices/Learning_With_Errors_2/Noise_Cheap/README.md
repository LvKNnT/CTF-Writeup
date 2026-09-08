# Noise Cheap Writeup

## Summary

This live LWE challenge runs at `socket.cryptohack.org:13413`. The error is multiplied by a known small factor `p`, which can be inverted modulo `q`; this transforms the problem into a standard small-error LWE instance. LLL recovers the error vector and then the secret key.

Flag:

```text
crypto{LLL_is_also_very_useful!}
```

## Triage

The solver uses:

```text
n = 64
p = 257
q = 1048583
```

It queries encryptions of `m = 0`, so every sample has the form:

```text
b = A*S + p*e mod q
```

## Solve Path

Because `p` is invertible modulo `q`, multiply by `p^-1`:

```text
b' = A*S*p^-1 + e mod q
```

Let `S' = S*p^-1`. Now the error vector is small, so the solver builds the LWE lattice with blocks `qI`, `A^T`, and `b'`, then runs LLL to recover `e`. With `e` known, it solves for `S'` and multiplies by `p` to get `S`.

The flag is decrypted one index at a time by trying the small error values `-1`, `0`, and `1`.

## Exploit

Use `solve.sage`. It:

- connects to `socket.cryptohack.org:13413`,
- collects 80 encryptions of zero,
- inverts the cheap-noise multiplier,
- recovers the error vector with LLL,
- solves for the secret and decrypts the flag.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_2/Noise_Cheap
sage solve.sage
```

Output:

```text
[+] Error vector recovered: (1, 0, 0, 0, 0)...
[+] Secret Key S recovered.
[+] Full Flag: crypto{LLL_is_also_very_useful!}
```

## Flag

```text
crypto{LLL_is_also_very_useful!}
```

## Lessons Learned

- Multiplying noise by an invertible constant does not necessarily make LWE safer.
- LLL can recover small error vectors from a primal lattice embedding.
- Chosen plaintext queries, such as encrypting zero, simplify secret recovery.
