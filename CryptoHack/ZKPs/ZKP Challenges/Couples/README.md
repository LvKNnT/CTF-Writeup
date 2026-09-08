# Couples Writeup

## Summary

Couples is a pairing-curve implementation challenge with a strange internal exponent knob. The solve sets that exponent to `p - 5`, which makes the verifier's algebra collapse by Fermat's little theorem and a buggy inverse-at-zero behavior, then submits a proof with the standard G1 generator.

Flag:

```text
crypto{don_t_let_useless_param_and_edge_cases_in_your_code}
```

## Triage

The service exposes options to set an internal value `z` and then run `do_proof`. The checked-in solver targets `socket.cryptohack.org:13415` and uses BN254's base field prime:

```python
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
G1 = (1, 2, 1)
```

## Solve Path

The exploit comment captures the core trick:

```text
power = p - 5 gives x^(power + 7) - x^3 = x^(p + 2) - x^3 = 0
```

For nonzero `x`, Fermat reduces `x^(p+2)` to `x^3`, so the expression cancels. The implementation also treats `inverse(0, p)` as `0`, making the edge case pass instead of failing.

The solver first sets the internal exponent:

```python
send_json(io, {"option": "set_internal_z", "z": hex(p - 5)})
```

Then it submits a proof request using `G1` and a small hash:

```python
send_json(io, {
    "option": "do_proof",
    "G": point_to_server(G1),
    "hsh": "0x1",
})
```

## Exploit

Use the standalone Sage script:

```bash
sage solve.sage
```

It connects to `socket.cryptohack.org:13415`, sets the internal exponent, submits the proof, and prints the server message.

## Verification

Verified live against `socket.cryptohack.org:13415` from WSL using the `sage` conda environment:

```text
crypto{don_t_let_useless_param_and_edge_cases_in_your_code}
```

## Flag

```text
crypto{don_t_let_useless_param_and_edge_cases_in_your_code}
```

## Lessons Learned

- Edge-case arithmetic behavior can invalidate pairing or curve checks.
- Fermat reductions can turn large exponent expressions into identities.
- Verifiers should reject invalid inversions instead of assigning them convenient values.
