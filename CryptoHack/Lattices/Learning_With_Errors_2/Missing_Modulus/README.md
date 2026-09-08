# Missing Modulus Writeup

## Summary

This live challenge runs at `socket.cryptohack.org:13412` and hides the modulus by working over real-number-style noisy samples. The solver collects many samples, applies least-squares regression to recover the secret, and then decrypts the flag.

Flag:

```text
crypto{learning-is-easy-over-the-real-numbers}
```

## Triage

The server source and solver show a noisy linear system. Unlike normal LWE, the attack treats the data as a regression problem instead of a modular lattice problem.

The solver collects:

```text
550 samples
```

## Solve Path

The samples are linear measurements of the secret plus small error. Over the real numbers, enough samples let the noise average out. The solver forms the overdetermined system and solves it with least squares:

```text
[*] Solving linear system (Least Squares)...
```

The recovered secret is then used to decrypt flag bytes from the service.

## Exploit

Use `solve.sage`. It:

- connects to `socket.cryptohack.org:13412`,
- collects 550 samples,
- solves for the secret with least squares,
- decrypts the flag byte by byte.

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_2/Missing_Modulus
sage solve.sage
```

Output:

```text
[+] Secret Key S recovered.
[+] Full Flag: crypto{learning-is-easy-over-the-real-numbers}
```

## Flag

```text
crypto{learning-is-easy-over-the-real-numbers}
```

## Lessons Learned

- Removing modular structure can make noisy linear systems vulnerable to regression.
- Many samples can average out bounded noise.
- Hiding a modulus does not help if the resulting problem is easier.
