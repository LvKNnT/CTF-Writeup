# Exceptional Curves Writeup

## Summary

This challenge uses an anomalous elliptic curve where the group order equals the field characteristic `p`. Such curves are vulnerable to Smart's attack. By lifting the curve and points to the `p`-adics, the elliptic-curve discrete log becomes a division of formal logarithms.

Flag:

```text
crypto{H3ns3l_lift3d_my_fl4g!}
```

## Triage

The Sage source and transcript provide an ECDH exchange and AES-CBC ciphertext. The first check is the curve order:

```text
Checking for Anomalous Curve...
Confirmed: Curve order equals p. Vulnerable to Smart's Attack.
```

That confirms this is not a generic ECDLP problem.

## Solve Path

Smart's attack works because anomalous curves have a useful homomorphism from the curve group into the additive field. The solver lifts the curve and points to a `p`-adic field, multiplies by the curve order, and computes:

```text
d = phi(Q) / phi(G) mod p
```

where `phi(P)` is derived from the lifted formal group coordinates. With Alice's private key recovered, the script performs the normal ECDH shared-secret derivation and decrypts the ciphertext.

## Exploit

The final solve is `solve.sage`. It:

- verifies `#E(F_p) = p`,
- performs the Hensel lift used by Smart's attack,
- recovers Alice's private key,
- derives the AES key and decrypts the flag.

Run it with:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice/Exceptional_Curves
sage solve.sage
```

Output:

```text
Confirmed: Curve order equals p. Vulnerable to Smart's Attack.
Found Private Key nA: 2200911270816846838022388357422161552282496835763864725672800875786994850585872907705630132325051034876291845289429009837283760741160188885749171857285407
FLAG: crypto{H3ns3l_lift3d_my_fl4g!}
```

## Flag

```text
crypto{H3ns3l_lift3d_my_fl4g!}
```

## Lessons Learned

- Anomalous curves with `#E(F_p) = p` are structurally weak.
- Smart's attack converts ECDLP on anomalous curves into arithmetic in a lifted formal group.
- Curve order validation is as important as validating the curve equation itself.
