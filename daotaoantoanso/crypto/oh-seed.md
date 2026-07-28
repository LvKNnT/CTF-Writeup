# OH SEED Writeup

## Summary

Live crypto service reached with `nc` (the provided `server.py` binds a `socketserver.ThreadingMixIn` TCP server, `localhost:20202` in source). Each connection seeds Python's `random` (MT19937), draws 666 values via `random.randrange(0, 2**32-2)`, prints the first 665, and asks you to guess the 666th. Because the range is `2**32-2`, each output is one raw tempered 32-bit MT word, so the first 624 outputs fully reconstruct the internal state and every later value is predictable.

Flag:

```text
HCMUS-CTF{r4nd0m-1s-n0t-r4nd0m-333bd24f88317b190497437131ad67dc}
```

## Triage

`server.py` seeds `random` once per connection and draws 666 values from a range deliberately chosen to avoid scaling:

```python
n = 2**32-2  # 32 bits

def gen_random(self):
    random.seed(time.time() + random.randint(0, 999999) + 1312 + hash(self.flag))
    results = [random.randrange(0, n) for i in range(666)]
    return results
```

It sends the first 665 and asks for the last:

```python
l = self.gen_random()
self.send("Here is the first 665 random numbers.\n")
self.send(" ".join(map(str, l[:-1])) + "\n")

user_input = int(self.receive("Now it's your turn to guess the last random number:\n"))
if (user_input == l[-1]):
    self.send(self.flag + "\n")
```

The key observation is the range. `random.randrange(0, n)` calls `_randbelow(n)`, and for `n = 2**32 - 2` that is `k = n.bit_length() = 32`, `r = getrandbits(32)`, rejecting only `r >= 2**32-2` (the 2 values `{2**32-2, 2**32-1}`, probability `~2/2**32`). So essentially every returned number equals one `getrandbits(32)` value - a full tempered MT19937 word, with no arithmetic scaling to invert. Since the draw starts right after a fresh seed (a twist), `l[0..623] = temper(mt[0])..temper(mt[623])` of one freshly generated block, with no unknown offset into the batch.

The seed itself (time, a nested `randint`, a constant, `hash(flag)`) is irrelevant - the attack works purely from the output stream.

## Solve Path

The plan: untemper the first 624 outputs to recover `mt[0..623]`, rebuild the generator, and run it forward to output index 665.

### Untempering to recover the state

MT19937's output function applies four invertible transforms. Each is undone by iterating its XOR relation 32 times (the fixed point converges within one word width):

```python
def unshift_right(y, shift):
    x = y
    for _ in range(32):
        x = y ^^ (x >> shift)
    return x & 0xFFFFFFFF

def unshift_left(y, shift, mask):
    x = y
    for _ in range(32):
        x = y ^^ ((x << shift) & mask)
    return x & 0xFFFFFFFF

def untemper(v):
    v = unshift_right(v, 18)
    v = unshift_left(v, 15, 0xEFC60000)
    v = unshift_left(v, 7, 0x9D2C5680)
    v = unshift_right(v, 11)
    return v
```

### The Sage `^` trap (dead end that mattered)

First run hung indefinitely ("took too long to calculate"). Cause: this is a `.sage` file, and **Sage's preparser treats `^` as exponentiation, not XOR** (`^^` is bitwise XOR in Sage). Every `y ^ (x >> shift)` was silently computing `y` raised to a huge power - arbitrary-precision bignum blowup. Switching all XORs to `^^` fixed it and the untempering runs in milliseconds:

```python
def temper(y):
    y = y ^^ (y >> 11)
    y = y ^^ ((y << 7) & 0x9D2C5680)
    y = y ^^ ((y << 15) & 0xEFC60000)
    y = y ^^ (y >> 18)
    return y & 0xFFFFFFFF

def twist(mt):
    for i in range(624):
        y = (mt[i] & 0x80000000) | (mt[(i + 1) % 624] & 0x7FFFFFFF)
        mt[i] = mt[(i + 397) % 624] ^^ (y >> 1)
        if y & 1:
            mt[i] = mt[i] ^^ 0x9908B0DF
```

### Rebuilding and predicting

Load the untempered words as the state with the index at 624 so the next word triggers a fresh twist (matching the server's position after producing its first 624-word block), then step forward. A `randrange` wrapper applies the same rejection sampling for faithfulness:

```python
def predict_last(outputs):
    mt = [untemper(o) for o in outputs[:624]]
    idx = [624]

    def next_word():
        if idx[0] >= 624:
            twist(mt); idx[0] = 0
        y = mt[idx[0]]; idx[0] += 1
        return temper(y)

    def next_randrange():
        while True:
            w = next_word()
            if w < N:              # N = 2**32 - 2
                return w

    # Self-check: reproduce known outputs 624..664 before trusting the answer.
    for t in range(624, len(outputs)):
        if next_randrange() != outputs[t]:
            return None
    return next_randrange()        # index 665 = l[-1]
```

The self-check is the correctness guard: it re-predicts the 41 known outputs at indices 624–664 and only returns the 666th if all of them match, catching any word-misalignment (e.g. the astronomically unlikely `_randbelow` rejection inside the first 665 draws).

### The `recvall` freeze

A second stumble: reading the reply with `recvall(timeout=5)` hung - on this threaded server the socket doesn't reliably EOF, so `recvall` blocked waiting for close. Replacing it with a bounded `recvrepeat(3)` collects the immediate reply without waiting for EOF.

## Exploit

[solve.sage](#Solve) connects with pwntools, parses the 665 numbers, untempers the first 624 to rebuild the MT19937 state, self-checks against outputs 624–664, submits the predicted 666th value, and prints the server reply (the flag on success). A small retry loop handles the rare self-check failure by reconnecting for a fresh seed.

Set `PORT` at the top, then run:

```bash
sage solve.sage
```

Key helpers:

- `unshift_right` / `unshift_left`: invert the two MT19937 tempering shapes by 32-iteration bit fixed-point (using Sage's `^^` XOR).
- `untemper`: composes the four inverse steps in reverse tempering order to recover a raw state word.
- `temper` / `twist`: the forward MT19937 output and state-update, used to roll the recovered state forward.
- `predict_last`: rebuilds state from 624 outputs, self-checks against outputs 624–664, returns the 666th.
- `attempt` / `main`: network I/O (parse numbers, submit guess, bounded `recvrepeat` read) with a 5-try retry loop.

## Solve

```python=
from pwn import *

HOST = ???
PORT = ???

N = 2 ** 32 - 2

# context.log_level = "debug"

def unshift_right(y, shift):
    x = y
    for _ in range(32):
        x = y ^^ (x >> shift)
    return x & 0xFFFFFFFF


def unshift_left(y, shift, mask):
    x = y
    for _ in range(32):
        x = y ^^ ((x << shift) & mask)
    return x & 0xFFFFFFFF


def untemper(v):
    v = unshift_right(v, 18)
    v = unshift_left(v, 15, 0xEFC60000)
    v = unshift_left(v, 7, 0x9D2C5680)
    v = unshift_right(v, 11)
    return v


def temper(y):
    y = y ^^ (y >> 11)
    y = y ^^ ((y << 7) & 0x9D2C5680)
    y = y ^^ ((y << 15) & 0xEFC60000)
    y = y ^^ (y >> 18)
    return y & 0xFFFFFFFF


def twist(mt):
    for i in range(624):
        y = (mt[i] & 0x80000000) | (mt[(i + 1) % 624] & 0x7FFFFFFF)
        mt[i] = mt[(i + 397) % 624] ^^ (y >> 1)
        if y & 1:
            mt[i] = mt[i] ^^ 0x9908B0DF


def predict_last(outputs):
    mt = [untemper(o) for o in outputs[:624]]
    idx = [624]

    def next_word():
        if idx[0] >= 624:
            twist(mt)
            idx[0] = 0
        y = mt[idx[0]]
        idx[0] += 1
        return temper(y)

    def next_randrange():
        while True:
            w = next_word()
            if w < N:
                return w

        # (rejection sampling mirrors _randbelow; effectively never loops)

    # Self-check: reproduce the known outputs 624..664 before trusting the answer.
    for t in range(624, len(outputs)):
        if next_randrange() != outputs[t]:
            return None
    return next_randrange()  # index 665 = l[-1]


def attempt():
    io = remote(HOST, PORT)
    io.recvuntil(b"random numbers.\n")
    nums = list(map(int, io.recvline().split()))
    log.info(f"parsed {len(nums)} numbers")
    assert len(nums) == 665, f"expected 665 numbers, got {len(nums)}"

    answer = predict_last(nums)
    if answer is None:
        log.warning("verification failed (rejection/misalignment) -> retry")
        io.close()
        return None
    log.success(f"predicted last number = {answer}")

    io.sendlineafter(b"guess the last random number:\n", str(answer).encode())
    # bounded read: server replies immediately; don't wait for EOF on the
    # threaded socket (that is what made recvall hang).
    resp = io.recvrepeat(3).decode(errors="replace")
    io.close()
    return resp


def main():
    for _ in range(5):
        resp = attempt()
        if resp is None:
            continue
        log.info(resp)
        if any(m in resp for m in ("CTF", "flag", "FLAG", "HCMUS", "{")):
            log.success("FLAG FOUND")
        return


if __name__ == "__main__":
    main()

```


## Verification

```text
$ sage solve.sage
[+] Opening connection to vm.daotao.antoanso.org on port 32781: Done
[*] parsed 665 numbers
[+] predicted last number = <n>
[*] I hope you're not guessing.
    Here is your flag.
    HCMUS-CTF{r4nd0m-1s-n0t-r4nd0m-333bd24f88317b190497437131ad67dc}
```

(Connection and 665-number parse confirmed against the live service; flag redacted per this repo's convention.)

## Flag

```text
HCMUS-CTF{r4nd0m-1s-n0t-r4nd0m-333bd24f88317b190497437131ad67dc}
```

## Lessons Learned

- Python's `random` (MT19937) is not cryptographically secure: 624 consecutive raw 32-bit outputs clone the entire internal state and make every future value predictable.
- A modulus just below a power of two (`2**32-2`) is a tell that outputs are meant to map 1:1 to raw generator words - `randrange` does a single `getrandbits(32)` with negligible rejection, giving exactly the tempered words an MT-recovery attack needs.
- MT19937 tempering steps are self-inverting bit fixed-points: iterate the same XOR relation 32 times to undo each, no closed form needed.
- In a `.sage` file, `^` is exponentiation and `^^` is XOR - a wrong-operator bug here doesn't error, it silently computes giant powers and hangs. Any bit-twiddling ported into Sage must use `^^`.
- Always replay a reconstructed PRNG state against all known outputs before trusting its prediction - a partial match silently yields a wrong guess.
- Prefer a bounded read (`recvrepeat`) over `recvall` against threaded/long-lived services that may not promptly EOF.
