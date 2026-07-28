# Permutation Writeup

## Summary

This is a live crypto service (`solve.sage` connects with `pwn.remote(HOST, PORT)`, i.e. `nc vm.daotao.antoanso.org 32790`). Each connection prints a fresh random permutation of 512 elements and that permutation raised to the power of the flag (interpreted as an integer exponent); since the order of a permutation on 512 elements is always small (bounded by the LCM of a partition of 512, far smaller than a typical flag-sized integer), each connection only leaks the flag modulo that permutation's order - repeated connections and CRT recombination eventually pin down the exact flag.

Flag:

```text
HCMUS-CTF{discrete_log_is_easy_on_permutation_group}
```

## Triage

`permutation.py` reads the flag as a big integer, generates a random permutation of `512` elements, and computes that permutation raised to the flag's power via fast exponentiation-by-squaring on permutation composition:

```python
def get_permutation(n : int) -> List[int]:
    arr = list(range(n))
    random.shuffle(arr)
    return arr

def compose_permutation(p1 : List[int], p2 : List[int]):
    return [p1[x] for x in p2]

def permutation_power(p : List[int], n : int) -> List[int]:
    if n == 0:
        return list(range(len(p)))
    if n == 1:
        return p
    x = permutation_power(p, n // 2)
    x = compose_permutation(x, x)
    if n % 2 == 1:
        x = compose_permutation(x, p)
    return x

with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), byteorder='big')

perm = get_permutation(512)
print(perm)
print(permutation_power(perm, flag))
```

The output is just two printed Python lists: the random permutation, and that permutation raised to the (huge, unknown) flag-integer power. There is no modulus and no encryption in the RSA sense - the "ciphertext" is a permutation, and the exponent is the actual secret.

## Solve Path

Any permutation of a finite set has a finite multiplicative order (the LCM of its cycle lengths). For `n = 512`, that order is at most a few tens of millions - far smaller than the flag interpreted as an integer (a multi-hundred-bit value). So `perm^flag` only reveals `flag mod order(perm)`, one residue per connection. The server draws a fresh random permutation each connection but always raises it to the *same* flag, so connecting repeatedly and combining residues via CRT converges on the exact flag once the combined modulus exceeds the flag's bit length:

```python
# order(perm) for n=512 is only ~2^20-2^30, far smaller than a typical flag.
# The server reuses the same `flag` exponent but draws a fresh random perm
# every connection, so we reconnect repeatedly and CRT the residues together
# until the combined modulus is large enough to pin down the exact flag.
MAX_ATTEMPTS = 512
```

For a single session, decompose the permutation into cycles:

```python
def cycle_decomposition(perm):
    n = len(perm)
    visited = [False] * n
    cycles = []
    for i in range(n):
        if visited[i]:
            continue
        cycle = []
        j = i
        while not visited[j]:
            visited[j] = True
            cycle.append(j)
            j = perm[j]
        cycles.append(cycle)
    return cycles
```

Within a single cycle of length `L`, `perm` acts as a cyclic shift: `cycle[k+1] = perm(cycle[k])`, so `perm^e(cycle[0])` lands on `cycle[e mod L]`. Since `result = perm^flag`, locating `result[cycle[0]]` inside the cycle directly gives `flag mod L` for that cycle - and every cycle in the permutation yields an independent congruence:

```python
def session_congruence(perm, result):
    residues = []
    moduli = []
    for cycle in cycle_decomposition(perm):
        L = len(cycle)
        if L == 1:
            continue
        target = result[cycle[0]]
        residues.append(cycle.index(target))
        moduli.append(L)
    if not residues:
        return 0, 1
    return CRT_list(residues, moduli), lcm(moduli)
```

CRTing across all cycles in one session already gives `flag mod lcm(all cycle lengths in that session)` (this is `order(perm)` or a multiple of the LCMs used). Each new connection contributes an independent modulus (a different random permutation's cycle structure), so successive sessions are combined into a running CRT accumulator:

```python
cur_val, cur_mod = Integer(0), Integer(1)
for attempt in range(1, MAX_ATTEMPTS + 1):
    perm, result = get_data()
    val, mod = session_congruence(perm, result)
    cur_val = crt(cur_val, Integer(val), cur_mod, Integer(mod))
    cur_mod = lcm(cur_mod, mod)
    if looks_like_flag(cur_val):
        ...
```

The stopping condition doesn't rely on knowing the flag's exact bit length in advance - it just checks whether the currently reconstructed integer decodes to a printable-ASCII byte string:

```python
def looks_like_flag(value):
    value = int(value)
    if value == 0:
        return False
    data = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return len(data) > 0 and all(32 <= b < 127 for b in data)
```

Once `cur_mod` exceeds the true flag's integer value, `cur_val` becomes exactly `flag` (CRT modular reconstruction below the modulus is exact), and it reliably looks like readable ASCII while any residual-modulus artifact wouldn't.

## Exploit

[solve.sage](#Solve) repeatedly connects to the service, extracts one CRT congruence per connection from the returned permutation's cycle structure, accumulates them with a running `crt`/`lcm`, and stops as soon as the reconstructed integer decodes to printable ASCII.

Run:

```bash
sage solve.sage
```

Key helpers:

- `get_data`: opens one connection and parses the printed `perm` and `result` lists.
- `cycle_decomposition`: splits a permutation into its disjoint cycles.
- `session_congruence`: turns one session's cycles into a single `(flag mod L, L)` congruence via CRT across cycles.
- `looks_like_flag`: decodes a candidate integer to bytes and checks for all-printable-ASCII as the stopping heuristic.
- `main`: drives the reconnect loop, accumulating congruences with `crt`/`lcm` until `looks_like_flag` succeeds or `MAX_ATTEMPTS` is exhausted.

## Solve

```python=
from pwn import *
import ast

HOST = "vm.daotao.antoanso.org"
PORT = 32792

# order(perm) for n=512 is only ~2^20-2^30, far smaller than a typical flag.
# The server reuses the same `flag` exponent but draws a fresh random perm
# every connection, so we reconnect repeatedly and CRT the residues together
# until the combined modulus is large enough to pin down the exact flag.
MAX_ATTEMPTS = 512


def get_data():
    io = remote(HOST, PORT)
    perm = ast.literal_eval(io.recvline().decode().strip())
    result = ast.literal_eval(io.recvline().decode().strip())
    io.close()
    return perm, result


def cycle_decomposition(perm):
    n = len(perm)
    visited = [False] * n
    cycles = []
    for i in range(n):
        if visited[i]:
            continue
        cycle = []
        j = i
        while not visited[j]:
            visited[j] = True
            cycle.append(j)
            j = perm[j]
        cycles.append(cycle)
    return cycles


def session_congruence(perm, result):
    # perm defines cycle[k+1] = perm(cycle[k]), so perm^e(cycle[0]) = cycle[e mod L].
    # result = perm^flag, so locating result[cycle[0]] inside the cycle gives flag mod L.
    residues = []
    moduli = []
    for cycle in cycle_decomposition(perm):
        L = len(cycle)
        if L == 1:
            continue
        target = result[cycle[0]]
        residues.append(cycle.index(target))
        moduli.append(L)

    if not residues:
        return 0, 1
    return CRT_list(residues, moduli), lcm(moduli)


def looks_like_flag(value):
    value = int(value)
    if value == 0:
        return False
    data = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    # bytes has no isprintable; consider printable ASCII range (32..126)
    return len(data) > 0 and all(32 <= b < 127 for b in data)


def main():
    cur_val, cur_mod = Integer(0), Integer(1)

    for attempt in range(1, MAX_ATTEMPTS + 1):
        perm, result = get_data()
        val, mod = session_congruence(perm, result)

        cur_val = crt(cur_val, Integer(val), cur_mod, Integer(mod))
        cur_mod = lcm(cur_mod, mod)
        print(f"[{attempt}] order={mod}  combined_modulus_bits={int(cur_mod).bit_length()}")

        if looks_like_flag(cur_val):
            flag_bytes = int(cur_val).to_bytes((int(cur_val).bit_length() + 7) // 8, byteorder="big")
            print("Recovered flag:", flag_bytes)
            return

    print("Did not converge after", MAX_ATTEMPTS, "attempts.")
    print("cur_val =", cur_val)
    print("cur_mod =", cur_mod)


if __name__ == "__main__":
    main()
```

## Verification

```text
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[1] order=574266  combined_modulus_bits=20
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[2] order=8058  combined_modulus_bits=30
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[3] order=1256225880  combined_modulus_bits=51
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
...
[156] order=69089020  combined_modulus_bits=413
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[157] order=4253340  combined_modulus_bits=413
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[158] order=173160  combined_modulus_bits=413
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[159] order=826704900  combined_modulus_bits=413
[+] Opening connection to vm.daotao.antoanso.org on port 32792: Done
[*] Closed connection to vm.daotao.antoanso.org port 32792
[160] order=8982  combined_modulus_bits=421
Recovered flag: b'HCMUS-CTF{discrete_log_is_easy_on_permutation_group}'
```

## Flag

```text
HCMUS-CTF{discrete_log_is_easy_on_permutation_group}
```

## Lessons Learned

- Using a secret as an *exponent* on a low-order algebraic structure (here, permutations of a small finite set) only leaks the secret modulo that structure's order - the secret itself may be far larger than any single leak can determine.
- A fresh random instance of the low-order structure per session is not a defense: each session is an independent modulus, and Chinese Remainder combination across many sessions reconstructs the full secret once the combined modulus exceeds it.
- Cycle decomposition turns "where does this element go under repeated application" into a simple index lookup within a cycle - a general technique for extracting a discrete-log-like residue mod cycle length without solving anything algorithmically.
- When there's no natural stopping bound (e.g. exact flag length unknown up front), a decode-and-sanity-check heuristic (printable ASCII) is a reliable, low-cost way to know when a progressively-refined CRT reconstruction has converged to the true value.
- Fast exponentiation (square-and-multiply) generalizes cleanly to any associative composition operation, including permutation composition - recognize `x^n` structure even when `x` isn't a number.
