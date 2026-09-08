# L-Win Writeup

## Summary

L-Win outputs a long bitstream generated from the flag bits through an LFSR. The solution recovers the linear recurrence with Berlekamp-Massey, back-clocks the register to the original flag state, and decodes the state as bytes.

Flag:

```text
crypto{minimal_polynomial_in_an_arbitrary_field}
```

## Triage

The challenge source initializes the LFSR state from the 48-byte flag, clocks it `16 * len(FLAG)` times, and then prints output bits. This means the observed stream starts after the original flag state has already advanced.

## Solve Path

The solver feeds the captured stream into Berlekamp-Massey:

```python
bm = BerlekampMassey(stream_str)
poly_set = bm.get_polynomial()
degree = bm.get_polynomial_degree()
```

The first `degree` output bits form a current state window. Since Berlekamp-Massey gives the recurrence relation, the script reverses the recurrence for `16 * 48` clocks to recover the initial 384 flag bits.

Finally it converts the recovered bitstring into an integer and then bytes:

```python
bits = "".join(map(str, state))
flag_int = int(bits, 2)
flag = long_to_bytes(flag_int)
```

## Exploit

The standalone exploit is `Misc/LFSR/L-Win/solve.py`, supported by `berlekamp_massey.py`.

```bash
python solve.py
```

## Verification

Verified in WSL using the `sage` conda environment:

```text
[*] Loaded stream of length 2048
[*] Recovered Polynomial Degree: 384
[*] Back-clocking 768 steps...
[*] Reversal complete. Decoding...

[+] FLAG: crypto{minimal_polynomial_in_an_arbitrary_field}
```

## Flag

```text
crypto{minimal_polynomial_in_an_arbitrary_field}
```

## Lessons Learned

- A long enough LFSR output reveals the minimal linear recurrence.
- Once the recurrence is known, an LFSR can be clocked backward as well as forward.
- Treating the flag itself as state makes the recovered initial state directly readable.
