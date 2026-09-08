# Elliptic Nodes Writeup

## Summary

This challenge gives an ECDH-style transcript on a singular cubic. Because the curve has a node, it is not a secure elliptic curve group; it can be mapped to a multiplicative group over the base field. The private key is recovered with a discrete logarithm after applying that singular-curve parametrization.

Flag:

```text
crypto{s1ngul4r_s1mplif1c4t1on}
```

## Triage

The source and output files define a Weierstrass equation, a generator `G`, a public key `Q`, and an encrypted secret. Factoring the cubic reveals a repeated root and a single root, which identifies the curve as singular.

The solver prints the recovered parameters and roots before solving the discrete log:

```text
double root: 1557923326969252180825193218688702224840389936248863823173183835359957757721
single root: 1252743530795041358577574745326954908754967315811591864173948822463623564261
```

## Solve Path

For a nodal cubic, the usual elliptic-curve group is isomorphic to a multiplicative subgroup. The solver maps each point `(x, y)` to:

```text
u = (y + alpha * (x - beta)) / (y - alpha * (x - beta))
```

where `beta` is the double root and `alpha^2 = 3 * beta + a`. After mapping both `G` and `Q`, the private key becomes:

```text
q = g^d mod p
```

That is solved with a finite-field discrete log, then submitted as the challenge secret.

## Exploit

The complete solve is in `solve.sage`. It:

- reconstructs the singular curve parameters,
- factors the cubic to find the node,
- maps `G` and `Q` into the multiplicative group,
- solves the discrete log with Sage,
- prints the CryptoHack answer.

Run it with:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice/Elliptic_Nodes
sage solve.sage
```

Output:

```text
Found private key: 175707932493016342199601625200584496546434097133638117913010244817446203005
The secret is: crypto{s1ngul4r_s1mplif1c4t1on}
```

## Flag

```text
crypto{s1ngul4r_s1mplif1c4t1on}
```

## Lessons Learned

- Singular curves are not elliptic curves and do not provide elliptic-curve security.
- Repeated roots in the curve polynomial are an immediate parameter-validation failure.
- Nodal cubics often reduce ECDLP to DLP in a much simpler finite-field group.
