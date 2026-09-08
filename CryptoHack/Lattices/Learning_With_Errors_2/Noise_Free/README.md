# Noise Free Writeup

## Summary

This live challenge runs at `socket.cryptohack.org:13411` and removes the noise from LWE. Without the error term, the samples are just linear equations modulo `q`, so the secret key is recovered by linear algebra.

Flag:

```text
crypto{linear_algebra_is_useful}
```

## Triage

The source file and solver show an oracle that returns equations of the form:

```text
b = A * S mod q
```

The solver collects 64 equations, matching the secret dimension.

## Solve Path

With no noise, LWE loses its hardness. The script collects enough independent equations and solves:

```text
A * S = b mod q
```

After recovering `S`, it queries flag indices and decrypts each character by subtracting the secret dot product.

## Exploit

Use `solve.sage`. It:

- connects to `socket.cryptohack.org:13411`,
- collects 64 equations,
- solves the modular linear system,
- decrypts the flag one byte at a time.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_2/Noise_Free
sage solve.sage
```

Output:

```text
[+] Secret Key S recovered!
[+] Full Flag: crypto{linear_algebra_is_useful}
```

## Flag

```text
crypto{linear_algebra_is_useful}
```

## Lessons Learned

- LWE without noise is only a linear algebra problem.
- Enough independent equations determine the secret exactly.
- Decryption after secret recovery is just subtracting the predicted linear term.
