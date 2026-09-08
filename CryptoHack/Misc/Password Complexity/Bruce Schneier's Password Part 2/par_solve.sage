#!/usr/bin/env sage
import argparse
import json
import multiprocessing as mp
import re
import socket


MOD = 2**64
SIGN = 2**63

DIGIT = 1 << 0
UPPER = 1 << 1
LOWER = 1 << 2
NEEDED = DIGIT | UPPER | LOWER


def int64(x):
    x %= MOD
    return x - MOD if x >= SIGN else x


def cls_mask(c):
    if c.isdigit():
        return DIGIT
    if c.isupper():
        return UPPER
    if c.islower():
        return LOWER
    return 0


def usable_chars():
    # The successful sum is an odd prime, so the product must be odd.  Any even
    # ASCII character makes the product even modulo 2^64 and can be skipped.
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
    return [(c, ord(c), cls_mask(c)) for c in alphabet if ord(c) % 2 == 1]


CHARS = usable_chars()


def np_sum(password):
    return int64(sum(map(ord, password)))


def np_prod(password):
    p = 1
    for c in password:
        p = (p * ord(c)) % MOD
    return int64(p)


def valid_shape(password):
    return (
        re.fullmatch(r"\w*", password, flags=re.ASCII)
        and re.search(r"\d", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
    )


def accepted(password):
    s = np_sum(password)
    return valid_shape(password) and s > 1 and is_prime(ZZ(s)) and s == np_prod(password)


def dfs(start, remaining, sum_mod, prod_mod, mask, out):
    if remaining == 0:
        s = int64(sum_mod)
        if mask == NEEDED and s > 1 and int64(prod_mod) == s and is_prime(ZZ(s)):
            return "".join(out)
        return None

    for i in range(start, len(CHARS)):
        c, v, bit = CHARS[i]
        out.append(c)
        found = dfs(
            i,
            remaining - 1,
            (sum_mod + v) % MOD,
            (prod_mod * v) % MOD,
            mask | bit,
            out,
        )
        if found is not None:
            return found
        out.pop()
    return None


def worker(task):
    length, first_index = task
    c, v, bit = CHARS[first_index]
    return dfs(first_index, length - 1, v, v % MOD, bit, [c])


def find_password(min_length, max_length, jobs):
    for length in range(min_length, max_length + 1):
        print(f"[*] length {length}")
        tasks = [(length, i) for i in range(len(CHARS))]

        if jobs == 1:
            for task in tasks:
                found = worker(task)
                if found:
                    return found
        else:
            with mp.Pool(processes=jobs) as pool:
                for found in pool.imap_unordered(worker, tasks, chunksize=1):
                    if found:
                        pool.terminate()
                        return found

    raise SystemExit(f"no password found for lengths [{min_length}, {max_length}]")


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
    parser = argparse.ArgumentParser(description="Parallel generator solve for Bruce Schneier's Password Part 2.")
    parser.add_argument("--min-length", type=int, default=3)
    parser.add_argument("--max-length", type=int, default=10)
    parser.add_argument("--jobs", type=int, default=max(1, mp.cpu_count() - 1))
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=13401)
    args = parser.parse_args()

    if args.min_length < 3:
        args.min_length = 3

    print("[*] usable chars =", "".join(c for c, _, _ in CHARS))
    password = find_password(args.min_length, args.max_length, args.jobs)
    assert accepted(password)

    print(f"password = {password}")
    print(f"sum      = {np_sum(password)}")
    print(f"product  = {np_prod(password)}")
    print(f"length   = {len(password)}")
    print(f"payload  = {json.dumps({'password': password})}")

    if args.host:
        banner, response = submit(args.host, args.port, password)
        print("banner   =", banner.strip())
        print("response =", response.strip())


if __name__ == "__main__":
    main()
