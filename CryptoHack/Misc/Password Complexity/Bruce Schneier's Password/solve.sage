#!/usr/bin/env sage
import argparse
import json
import re
import socket


MOD = 2**64
SIGN_BIT = 2**63

def np_int64_product(chars):
    """Return the same signed int64 value as numpy.array(...).prod()."""
    x = 1
    for c in chars:
        x = (x * ord(c)) % MOD
    if x >= SIGN_BIT:
        x -= MOD
    return x


def valid_shape(password):
    return (
        re.fullmatch(r"\w*", password, flags=re.ASCII)
        and re.search(r"\d", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
    )


def challenge_accepts(password):
    total = sum(map(ord, password))
    product = np_int64_product(password)
    return total > 1 and product > 1 and is_prime(total) and is_prime(product)


def find_password(max_count):
    # Use only odd byte values. If any character code were even, the overflowed
    # product would be even and therefore composite.
    chars = [("A", ord("A")), ("a", ord("a")), ("1", ord("1"))]
    powers = {}
    for _, value in chars:
        powers[value] = [1]
        for _ in range(max_count):
            powers[value].append((powers[value][-1] * value) % MOD)

    attempts = 0
    for n_upper in range(1, max_count + 1):
        upper_product = powers[ord("A")][n_upper]
        for n_lower in range(1, max_count - n_upper + 1):
            base_product = (upper_product * powers[ord("a")][n_lower]) % MOD
            base_sum = ord("A") * n_upper + ord("a") * n_lower
            for n_digit in range(1, max_count - n_upper - n_lower + 1):
                attempts += 1
                total = base_sum + ord("1") * n_digit
                if not is_prime(total):
                    continue

                product = (base_product * powers[ord("1")][n_digit]) % MOD
                if product >= SIGN_BIT:
                    product -= MOD

                if product > 1 and is_prime(product):
                    password = "A" * n_upper + "a" * n_lower + "1" * n_digit
                    return password, total, product, attempts

    raise SystemExit(f"no password found with total length <= {max_count}")


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
    parser = argparse.ArgumentParser(description="Solve CryptoHack Bruce Schneier's Password.")
    parser.add_argument("--max-count", type=int, default=256, help="maximum password length to search")
    parser.add_argument("--host", help="submit to a listener host after finding a password")
    parser.add_argument("--port", type=int, default=13400, help="listener port")
    args = parser.parse_args()

    if args.max_count < 3:
        raise SystemExit("max-count must be at least 3")

    password, total, product, attempts = find_password(args.max_count)
    assert valid_shape(password)
    assert challenge_accepts(password)

    print(f"password = {password}")
    print(f"sum      = {total}")
    print(f"product  = {product}")
    print(f"attempts = {attempts}")
    print(f"payload  = {json.dumps({'password': password})}")

    if args.host:
        banner, response = submit(args.host, args.port, password)
        print("banner   =", banner.strip())
        print("response =", response.strip())


if __name__ == "__main__":
    main()
