# LWE Low Bits Message Writeup

## Summary

This LWE warm-up encodes the message in the low bits of a modular sample. The solver removes the linear secret component and reads the low-bit message value.

Answer:

```text
147
```

## Triage

The folder contains the challenge Sage file, output transcript, and `solve.sage`. The transcript has the sample values needed for local recovery.

## Solve Path

The LWE sample is:

```text
b = <a, s> + message + error mod q
```

Here the message sits in the low bits. After subtracting the known dot product, the script reduces the result modulo the message base and prints the recovered byte.

## Exploit

Run:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_1/LWE_Low_Bits_Message
sage solve.sage
```

Output:

```text
147
```

## Flag

```text
147
```

## Lessons Learned

- Low-bit message encodings can be recovered with modular reduction after removing the secret term.
- LWE decryption is a rounding or reduction problem once the secret contribution is known.
- Small toy LWE examples are useful for recognizing the structure used in larger attacks.
