# An Exceptional Twisted Mind Writeup

## Summary

This live challenge runs at `socket.cryptohack.org:13417` and uses a modulus `p = q^2`. Instead of needing a twist, the square-prime modulus lets us lift the computation to the `q`-adics and apply an anomalous-style formal logarithm attack. Dividing the lifted logs recovers the private scalar.

Flag:

```text
crypto{no_need_for_twist_with_anomalous_attack_on_lift!}
```

## Triage

The source sets:

```text
p = q^2
q = 2^256 - 189
```

That is the main parameter flaw. The server accepts `get_pubkey` with an x-coordinate and later `get_flag` with the private key.

## Solve Path

The solver chooses a valid base x-coordinate over `GF(q)` and requests the server's multiplied x-coordinate modulo `q^2`. It then lifts both points to `Qp(q, 2)`:

```python
Qq = Qp(q, 2)
Eq = EllipticCurve(Qq, [a, b])
P_padic = Eq.lift_x(Qq(x0))
Q_padic = Eq.lift_x(Qq(res_x_mod_p))
```

Multiplying by the base curve order projects the points into the formal group. The scalar is recovered with:

```python
d_recovered = Integer(log_Q / log_P) % q
```

Because x-coordinates lose the sign of the y-coordinate, the solver tries `d` and `-d`.

## Exploit

Use `solve.sage`. It:

- generates a valid x-coordinate over `GF(q)`,
- queries `socket.cryptohack.org:13417`,
- performs the `q`-adic lift,
- recovers the private scalar via formal logarithms,
- submits the scalar to retrieve the flag.

Run it with:

```bash
sage solve.sage
```

## Verification

```bash
cd /mnt/e/APCS/CTF/training/crypto/cryptohack/Elliptic_Curves/Parameter_Choice_2/An_Exceptional_Twisted_Mind
sage solve.sage
```

Output:

```text
[*] Recovered true private key: 14968988153975241066611523508638494354687190313185123111658857492278393057982
{"message": "Congratulations, you found my private key.", "flag": "crypto{no_need_for_twist_with_anomalous_attack_on_lift!}"}
```

## Flag

```text
crypto{no_need_for_twist_with_anomalous_attack_on_lift!}
```

## Lessons Learned

- Moduli of the form `q^2` can expose p-adic lifting attacks.
- Formal group logarithms can turn lifted scalar multiplication into scalar division.
- X-only APIs still require sign handling when reconstructing private keys.
