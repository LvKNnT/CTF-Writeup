#!/usr/bin/env sage
import argparse
import json
import multiprocessing as mp
import re
import socket


MOD = 2**64
SIGN = 2**63

# Odd ASCII word characters only.  len(ALPHABET) == 32, so every integer can be
# viewed as a base-32 password candidate over this alphabet.
ALPHABET = "13579ACEGIKMOQSUWYacegikmoqsuwy_"
BASE = len(ALPHABET)


def int64(x):
    x %= MOD
    return x - MOD if x >= SIGN else x


def to_base32_password(n, length=None):
    if n == 0:
        s = ALPHABET[0]
    else:
        out = []
        while n:
            n, r = divmod(n, BASE)
            out.append(ALPHABET[int(r)])
        s = "".join(reversed(out))

    if length is not None:
        if len(s) > length:
            return None
        s = ALPHABET[0] * (length - len(s)) + s
    return s


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
    p = np_prod(password)
    return valid_shape(password) and s > 1 and is_prime(ZZ(s)) and s == p


def check_range(task):
    start, stop, length, verbose_every = task
    for i in range(start, stop):
        password = to_base32_password(i, length)
        if password is None:
            continue

        s = np_sum(password)
        p = np_prod(password)

        if verbose_every and i % verbose_every == 0:
            print(f"i={i} password={password} sum={s} product={p}")

        if valid_shape(password) and s > 1 and is_prime(ZZ(s)) and s == p:
            return i, password, s, p
    return None


def chunks(start, stop, chunk_size, length, verbose_every):
    x = start
    while x < stop:
        y = min(x + chunk_size, stop)
        yield (x, y, length, verbose_every)
        x = y


def search(start, stop, length, jobs, chunk_size, verbose_every):
    if jobs == 1:
        for task in chunks(start, stop, chunk_size, length, verbose_every):
            found = check_range(task)
            if found:
                return found
        return None

    with mp.Pool(processes=jobs) as pool:
        tasks = chunks(start, stop, chunk_size, length, verbose_every)
        for found in pool.imap_unordered(check_range, tasks, chunksize=1):
            if found:
                pool.terminate()
                return found
    return None


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
    parser = argparse.ArgumentParser(description="Base-32 generator solve for Bruce Schneier's Password Part 2.")
    parser.add_argument("--start", type=Integer, default=0)
    parser.add_argument("--stop", type=Integer, default=BASE**6)
    parser.add_argument("--length", type=int, help="left-pad candidates to this fixed password length")
    parser.add_argument("--jobs", type=int, default=max(1, mp.cpu_count() - 1))
    parser.add_argument("--chunk-size", type=int, default=10000)
    parser.add_argument("--verbose-every", type=int, default=0)
    parser.add_argument("--demo", type=Integer, help="show one base-10 integer converted to a base-32 password")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=13401)
    args = parser.parse_args()

    print(f"alphabet = {ALPHABET}")
    print(f"base     = {BASE}")

    if args.demo is not None:
        password = to_base32_password(args.demo, args.length)
        print(f"i        = {args.demo}")
        print(f"password = {password}")
        print(f"sum      = {np_sum(password)}")
        print(f"product  = {np_prod(password)}")
        print(f"accepted = {accepted(password)}")
        return

    found = search(args.start, args.stop, args.length, args.jobs, args.chunk_size, args.verbose_every)
    if not found:
        raise SystemExit(f"no password found for i in [{args.start}, {args.stop})")

    i, password, s, p = found
    print(f"i        = {i}")
    print(f"password = {password}")
    print(f"sum      = {s}")
    print(f"product  = {p}")
    print(f"length   = {len(password)}")
    print(f"payload  = {json.dumps({'password': password})}")

    if args.host:
        banner, response = submit(args.host, args.port, password)
        print("banner   =", banner.strip())
        print("response =", response.strip())


if __name__ == "__main__":
    main()
