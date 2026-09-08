#!/usr/bin/env sage
import argparse
import json
import re
import socket


MOD = 2**64
SIGN = 2**63
DIGIT = 1
UPPER = 2
LOWER = 4
NEEDED = DIGIT | UPPER | LOWER


CHARS = "13579ACEGIKMOQSUWYacegikmoqsuwy_"


def int64(x):
    x %= MOD
    return x - MOD if x >= SIGN else x


def class_mask(c):
    if c.isdigit():
        return DIGIT
    if c.isupper():
        return UPPER
    if c.islower():
        return LOWER
    return 0


def valid_shape(password):
    return (
        re.fullmatch(r"\w*", password, flags=re.ASCII)
        and re.search(r"\d", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
    )


def accepted(password):
    s = int64(sum(map(ord, password)))
    p = 1
    for c in password:
        p = (p * ord(c)) % MOD
    return valid_shape(password) and s > 1 and is_prime(ZZ(s)) and int64(p) == s


def dfs(target, index, remaining, remaining_len, product, mask, counts, values, masks):
    if remaining == 0:
        if remaining_len == 0 and mask == NEEDED and int64(product) == target:
            password = "".join(CHARS[i] * int(counts[i]) for i in range(len(CHARS)))
            if accepted(password):
                return password
        return None

    if index == len(CHARS):
        return None
    if remaining_len < 0:
        return None

    if remaining_len == 0:
        return None

    min_value = min(values[index:])
    max_value = max(values[index:])
    if remaining < remaining_len * min_value:
        return None
    if remaining > remaining_len * max_value:
        return None

    v = values[index]
    max_count = min(remaining_len, remaining // v)

    # Try larger counts first because overflow needs multiplicative weight.
    for k in range(max_count, -1, -1):
        counts[index] = k
        next_remaining = remaining - k * v
        next_product = (product * power_mod(v, k, MOD)) % MOD
        next_mask = mask | (masks[index] if k else 0)

        found = dfs(
            target,
            index + 1,
            next_remaining,
            remaining_len - k,
            next_product,
            next_mask,
            counts,
            values,
            masks,
        )
        if found:
            return found

    counts[index] = 0
    return None


def solve_target(target, length=None):
    if target <= 1 or not is_prime(ZZ(target)):
        return None

    values = [ord(c) for c in CHARS]
    masks = [class_mask(c) for c in CHARS]
    counts = [0] * len(CHARS)
    if length is None:
        min_len = ceil(ZZ(target) / max(values))
        max_len = floor(ZZ(target) / min(values))
        lengths = range(max(3, int(min_len)), int(max_len) + 1)
    else:
        lengths = [length]

    for L in lengths:
        found = dfs(ZZ(target), 0, ZZ(target), L, ZZ(1), 0, counts, values, masks)
        if found:
            return found
    return None


def find_password(min_sum, max_sum, length=None):
    for target in prime_range(max(3, min_sum), max_sum + 1):
        if target == 2:
            continue
        print(f"[*] trying sum {target}")
        password = solve_target(target, length)
        if password:
            return password
    raise SystemExit(f"no password found for prime sums in [{min_sum}, {max_sum}]")


def recv_json_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="replace")


def submit(host, port, password):
    with socket.create_connection((host, port)) as sock:
        banner = recv_json_line(sock)
        sock.sendall(json.dumps({"password": password}).encode() + b"\n")
        response = recv_json_line(sock)
    return banner, response


def main():
    parser = argparse.ArgumentParser(description="Count DFS solve for Bruce Schneier's Password Part 2.")
    parser.add_argument("--target", type=int, help="try one fixed prime sum, e.g. 499")
    parser.add_argument("--length", type=int, help="try one fixed password length")
    parser.add_argument("--min-sum", type=int, default=211)
    parser.add_argument("--max-sum", type=int, default=2000)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=13401)
    args = parser.parse_args()

    if args.target is not None:
        password = solve_target(args.target, args.length)
        if not password:
            raise SystemExit(f"no password found for target sum {args.target}")
    else:
        password = find_password(args.min_sum, args.max_sum, args.length)

    assert accepted(password)
    s = int64(sum(map(ord, password)))
    p = 1
    for c in password:
        p = (p * ord(c)) % MOD

    print(f"password = {password}")
    print(f"sum      = {s}")
    print(f"product  = {int64(p)}")
    print(f"length   = {len(password)}")
    print(f"payload  = {json.dumps({'password': password})}")

    if args.host:
        banner, response = submit(args.host, args.port, password)
        print("banner   =", banner.strip())
        print("response =", response.strip())


if __name__ == "__main__":
    main()
