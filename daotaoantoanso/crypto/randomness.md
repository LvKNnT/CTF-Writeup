# Randomness Writeup

## Summary

Offline crypto challenge: `randomness.py` runs locally and writes a single `output.txt` containing 27 integers, each a dot product of a random 46-coefficient vector (coefficients in `[1, 2^16]`) against the 46 flag character codes. The random coefficients come from Python's `random` module seeded with `int(time.time())` - a low-entropy, guessable seed - so the coefficient vectors can be regenerated exactly, turning flag recovery into solving a linear system (via lattice reduction) once the seed is brute-forced over a narrow timestamp window.

Flag:

```text
0160ca14{https://cryptohack.org/user/Archive/}
```

## Triage

`randomness.py` seeds `random` with the current Unix timestamp, then builds 27 linear equations over the 46 flag bytes:

```python
FLAG = b"0160ca14{????????????????????????????????????}"
variable_list = list(FLAG)

seed = int(time.time())
random.seed(seed)

coefficients_list = []
for i in range(27):
    coefficients = []
    for j in range(len(FLAG)):
        coefficients.append(random.randint(1, 2**16))
    coefficients_list.append(coefficients)

value_list = []
for vector in coefficients_list:
    value_list.append(scalar_multiplication(vector, variable_list))

with open("output.txt", "w") as file:
    file.write(f"{value_list = }")
```

That's 27 known linear equations (`value_list[i] = sum_j coeff[i][j] * flag[j]`) in 46 unknown bytes (`flag[j]`, each in printable-ASCII range) - badly underdetermined by ordinary linear algebra (27 equations, 46 unknowns), but the coefficients themselves are fully recoverable once the seed is known, and the seed is just `int(time.time())` at the moment the script ran. `output.txt` is small - just the 27 output values:

```
value_list = [123790633, 156591608, 147000916, 125772724, 131152757, 152644709, 144001980, 112930002, 118794552, ...]
```

The flag format `0160ca14{...}` fixes 9 leading bytes and 1 trailing `}`, further constraining the search - but the real break is the seed.

## Solve Path

Since the seed is `int(time.time())`, and the challenge's approximate creation time is known (from file metadata / submission time), the seed only needs to be brute-forced over a small window of candidate Unix timestamps around that value:

```python
date = "5/15/2025 11:26:35 AM"
approx_timestamp = int(time.mktime(time.strptime(date, "%m/%d/%Y %I:%M:%S %p")))

# check ngược 10000s
for offset in range(10000):
    seed = approx_timestamp - offset
    random.seed(seed)
```

For each candidate seed, regenerate the exact same 27x46 coefficient matrix `random` would have produced:

```python
    coefficients_list = []
    for i in range(27):
        coefficients = []
        for j in range(46):
            coefficients.append(random.randint(1, 2**16))
        coefficients_list.append(coefficients)
```

Even with the correct coefficients, 27 equations in 46 unknowns is still underdetermined for plain Gaussian elimination - but each unknown is a *small* integer (a printable byte, roughly 0-127), which is exactly the shape lattice-basis reduction (LLL) is built to exploit: find a short vector in the lattice of integer combinations that hits the target sums. The solver builds an augmented lattice basis with an identity block for the flag-byte unknowns, appends the coefficient columns, and appends a row encoding `-value_list` so a lattice vector that reproduces the flag makes the combination cancel to zero:

```python
    rows = []
    for i in range(46):
        row = [0] * 46
        row[i] = 1
        for j in range(27):
            row.append(coefficients_list[j][i])
        rows.append(row)

    last_row = [0] * 46
    for j in range(27):
        last_row.append(-value_list[j])
    rows.append(last_row)

    B = matrix(ZZ, rows)
    L = B.LLL()
```

Any reduced basis row whose trailing 27 entries (the equation-residual columns) are all zero has its leading 46 entries as a candidate flag-byte vector - LLL finds this because it's the shortest vector consistent with the linear constraints, and small-byte-valued solutions are short:

```python
    for row in L:
        if all(x == 0 for x in row[46:]):
            try:
                chars = [chr(x) for x in row[:46]]
                flag_candidate = "".join(chars)
                if "0160ca14{" in flag_candidate:
                    print(f"Seed: {seed}")
                    print(f"Flag: {flag_candidate}")
                    exit()
            except Exception:
                pass
```

The known flag prefix `0160ca14{` doubles as the correctness check that both confirms the right seed and rules out sign-flipped / scaled LLL output rows (LLL can return `-v` as easily as `v`).

## Exploit

[solve.sage](#Solve) brute-forces `random`'s seed over a 10000-second window around an approximate known timestamp, regenerates the coefficient matrix for each candidate seed exactly as the challenge did, and uses LLL on an augmented lattice to recover the small-byte flag vector consistent with the observed dot products, stopping as soon as a candidate contains the known flag prefix. Run with:

```
sage solve.sage
```

Key steps in the script:
- `approx_timestamp` - a known/estimated creation time anchoring the seed search
- `for offset in range(10000): seed = approx_timestamp - offset` - brute-forces the `time.time()`-based seed
- regenerating `coefficients_list` via `random.seed(seed)` + `random.randint(1, 2**16)` - reproduces the exact challenge RNG stream
- augmented lattice `rows` (identity block + coefficient columns + `-value_list` row) fed to `matrix(ZZ, rows).LLL()` - recovers small integer unknowns from underdetermined linear equations
- prefix check `"0160ca14{" in flag_candidate` - confirms the correct seed/LLL row and terminates the search

## Solve

```python=
import time
import random
import random
import time
from z3 import *

value_list = value_list = [123790633, 156591608, 147000916, 125772724, 131152757, 152644709, 144001980, 112930002, 118794552, 150363810, 132253260, 129427768, 125337368, 132414473, 139338226, 121261563, 134915261, 133063748, 129569576, 135580576, 141567869, 142129037, 150793830, 139504515, 143094641, 143348690, 133597992]

date = "5/15/2025 11:26:35 AM"
approx_timestamp = int(time.mktime(time.strptime(date, "%m/%d/%Y %I:%M:%S %p")))

for offset in range(10000):
    seed = approx_timestamp - offset
    random.seed(seed)
    
    coefficients_list = []
    for i in range(27):
        coefficients = []
        for j in range(46):
            coefficients.append(random.randint(1, 2**16))
        coefficients_list.append(coefficients)
            
    rows = []
    for i in range(46):
        row = [0] * 46
        row[i] = 1 
        
        for j in range(27):
            row.append(coefficients_list[j][i])
            
        rows.append(row)
        
    last_row = [0] * 46
    for j in range(27):
        last_row.append(-value_list[j])
    rows.append(last_row)
    
    B = matrix(ZZ, rows)
    L = B.LLL()
    
    for row in L:
        if all(x == 0 for x in row[46:]):
            
            try:
                chars = [chr(x) for x in row[:46]]
                flag_candidate = "".join(chars)
                
                if "0160ca14{" in flag_candidate:
                    print(f"Seed: {seed}")
                    print(f"Flag: {flag_candidate}")
                    exit()
            except Exception:
                pass
                
    if offset % 60 == 0 and offset > 0:
        print(f"Current: {offset}")
```

## Verification

```text
Seed: 1747283195
Flag: 0160ca14{https://cryptohack.org/user/Archive/}
```

## Flag

```text
0160ca14{https://cryptohack.org/user/Archive/}
```

## Lessons Learned

- Seeding a PRNG from a low-entropy, guessable source (`int(time.time())`) reduces "cryptographically random" coefficients to a small brute-forceable search space once an approximate generation time is known.
- An underdetermined linear system (fewer equations than unknowns) is still breakable when the unknowns are constrained to a small range (e.g. printable bytes) - lattice reduction (LLL) finds short/small integer solutions that ordinary linear algebra can't uniquely pin down.
- Encoding a linear system as a lattice basis (identity block for unknowns + coefficient columns + a target row) is a general pattern for turning "solve Ax=b over small integers" into "find a short vector," not specific to this challenge.
- A known plaintext/flag format (prefix, suffix, charset) is valuable beyond framing the problem - use it as the terminating correctness oracle when brute-forcing over an auxiliary parameter like a seed.
