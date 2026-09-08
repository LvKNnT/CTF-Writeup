# An Evil Twisted Mind Writeup

## Summary

This live challenge uses an x-only ladder over a composite modulus at `socket.cryptohack.org:13418`. The modulus factors are recoverable from the provided source, so we can craft one malicious x-coordinate that lands on twists modulo both prime factors. Solving smooth subgroup logs modulo each factor and combining them recovers the server's private key.

Flag:

```text
crypto{tw0_twists_for_th3_price_of_0ne}
```

## Triage

The solver has the endpoint hard-coded:

```python
HOST = "socket.cryptohack.org"
PORT = 13418
```

The server modulus is `n = p * q`, and the source exposes both prime factors. That means the same submitted integer `x0` can be controlled separately modulo `p` and modulo `q` with CRT.

## Solve Path

For each prime factor, the script chooses an x-coordinate where the curve RHS is a quadratic non-residue. This forces the arithmetic onto the quadratic twist. It then combines the two x-coordinates:

```python
x0_int = int(crt([int(xp), int(xq)], [p, q]))
```

The server multiplies this malicious x-coordinate by its secret scalar. Locally, the solver reconstructs the corresponding twist points modulo `p` and `q`, factors their orders, and solves discrete logs in smooth subgroups. The recovered residues cover more than 192 bits, enough to reconstruct the private scalar with CRT.

## Exploit

Use `solve.sage`. It:

- crafts a CRT x-coordinate that is invalid over both prime factors,
- queries `get_pubkey`,
- solves twist subgroup DLPs modulo `p` and `q`,
- combines all residues,
- submits the recovered private key.

Run it with:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice_2/An_Evil_Twisted_Mind
sage solve.sage
```

Output:

```text
[*] Total smooth product size: ~192.88 bits (Need > 192)
[+] Recovered Private Key Candidate: 1081636471064066731534206282304807519937152247345479780473
[+] SUCCESS! Flag: crypto{tw0_twists_for_th3_price_of_0ne}
```

## Flag

```text
crypto{tw0_twists_for_th3_price_of_0ne}
```

## Lessons Learned

- Composite-modulus ECC can fail separately modulo each prime factor.
- CRT can be used both to craft malicious inputs and to combine recovered residues.
- Invalid-curve and twist attacks become stronger when the implementation exposes x-only scalar multiplication without validation.
