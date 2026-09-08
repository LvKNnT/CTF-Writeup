# LWE High Bits Message Writeup

## Summary

This LWE warm-up encodes the message in the high bits of a modular sample. The solver subtracts the known inner product component and extracts the message value from the high-bit region.

Answer:

```text
201
```

## Triage

The folder contains the original Sage challenge, output transcript, and `solve.sage`. The output gives the LWE sample data needed to evaluate the decryption expression locally.

## Solve Path

An LWE sample has the form:

```text
b = <a, s> + encoded_message + error mod q
```

For this challenge, the message is placed in the high bits, so after subtracting `<a, s>` the remaining value can be scaled or rounded back to the message byte.

## Exploit

Run:

```bash
sage solve.sage
```

The solver evaluates the decryption arithmetic and prints the recovered message byte.

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Lattices/Learning_With_Errors_1/LWE_High_Bits_Message
sage solve.sage
```

Output:

```text
201
```

## Flag

```text
201
```

## Lessons Learned

- LWE encryption usually hides messages by adding them to noisy linear equations.
- If the secret or sample structure is known, decryption is just modular subtraction and rounding.
- Encoding location matters: high-bit encodings are recovered differently from low-bit encodings.
