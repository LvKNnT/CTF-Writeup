# Montgomerys Ladder40 Writeup

## Summary

This challenge asks for the result of a Montgomery ladder scalar multiplication. The provided solver implements the ladder on the given Montgomery curve and computes `k * P` for the challenge scalar. The final answer is the resulting point.

Answer:

```text
Point(x=49231350462786016064336756977412654793383964726771892982507420921563002378152, y=12119005339632834459469309411129861912584664210865168553689096898112464563298)
```

## Triage

Only `solve.py` is needed. It defines the curve parameters, point type, differential addition/doubling operations, and the challenge scalar:

```text
k = 0x1337C0DECAFE
```

## Solve Path

Montgomery's ladder performs scalar multiplication with a regular double-and-add pattern. The solver maintains two related points and processes the scalar bits from high to low, updating the pair with the Montgomery formulas.

Since the task is computational rather than cryptanalytic, the main requirement is implementing the formulas exactly and printing the final point.

## Exploit

Use `solve.py`. It:

- defines the Montgomery curve arithmetic,
- runs the ladder for `0x1337C0DECAFE`,
- prints the resulting point.

Run it with:

```bash
python solve.py
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Side_Channels/Montgomerys_Ladder40
python solve.py
```

Output:

```text
Point(x=49231350462786016064336756977412654793383964726771892982507420921563002378152, y=12119005339632834459469309411129861912584664210865168553689096898112464563298)
```

## Flag

```text
Point(x=49231350462786016064336756977412654793383964726771892982507420921563002378152, y=12119005339632834459469309411129861912584664210865168553689096898112464563298)
```

## Lessons Learned

- Montgomery ladders provide a regular scalar-multiplication structure.
- Formula transcription matters: a small arithmetic mistake changes the final point.
- Not every CryptoHack task yields a `crypto{...}` string; some ask for a computed value.
