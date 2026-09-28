#!/usr/bin/env sage
"""Recover the hosted Baby Circuit key or decrypt a supplied ciphertext.

Usage:
    sage decrypt.sage
    sage decrypt.sage HOST PORT
    sage decrypt.sage --key HEX --iv HEX --ciphertext HEX

With no arguments, decrypt the bundled local TEST fixture. This needs its Linux
x86_64 CPython 3.11 extension and reads the key through the test-only API.
With HOST PORT, recover the registers using the hosted two-proof oracle and
decrypt that session's ciphertext. The script uses the Sage conda environment.
"""

import argparse
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from baby_circuit_solver import remote_solve


def hex_bytes(value):
    try:
        return bytes.fromhex(value.removeprefix("0x"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected hexadecimal bytes") from exc


def decrypt(key, iv, ciphertext):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must contain 16, 24, or 32 bytes")
    if len(iv) != AES.block_size:
        raise ValueError("IV must contain 16 bytes")
    if not ciphertext or len(ciphertext) % AES.block_size:
        raise ValueError("ciphertext must contain a positive multiple of 16 bytes")
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)


def local_test():
    public = Path(__file__).resolve().parent / "public"
    sys.path.insert(0, str(public))
    import hw_model
    import hsm_main

    session = hsm_main.Session()
    try:
        session.ensure()
        plaintext = decrypt(hw_model.session_key(session.h), session.iv,
                            bytes.fromhex(session.enc))
        if plaintext != hsm_main.FLAG:
            raise ValueError("local plaintext verification failed")
        return plaintext
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--local-test", action="store_true",
                        help="decrypt the bundled TEST fixture (the default)")
    parser.add_argument("--key", type=hex_bytes)
    parser.add_argument("--iv", type=hex_bytes)
    parser.add_argument("--ciphertext", type=hex_bytes)
    parser.add_argument("target_host", nargs="?")
    parser.add_argument("target_port", nargs="?", type=int)
    parser.add_argument("--host", dest="host_opt")
    parser.add_argument("--port", dest="port_opt", type=int)
    parser.add_argument("--timeout", type=float, default=300,
                        help="oracle socket timeout in seconds (default: 300)")
    args = parser.parse_args()
    supplied = (args.key, args.iv, args.ciphertext)
    host = args.host_opt if args.host_opt is not None else args.target_host
    port = args.port_opt if args.port_opt is not None else args.target_port
    remote_requested = host is not None or port is not None
    if args.local_test and any(value is not None for value in supplied):
        parser.error("--local-test cannot be combined with key, IV, or ciphertext")
    if args.local_test and remote_requested:
        parser.error("--local-test cannot be combined with a remote target")
    if remote_requested and any(value is not None for value in supplied):
        parser.error("a remote target cannot be combined with --key, --iv, or --ciphertext")
    if remote_requested and (host is None or port is None):
        parser.error("provide both HOST and PORT")
    if any(value is not None for value in supplied) and any(value is None for value in supplied):
        parser.error("provide all of --key, --iv, and --ciphertext")
    try:
        if remote_requested:
            result = remote_solve(host, port, args.timeout)
            print(json.dumps(result, indent=2))
            return
        plaintext = (local_test() if args.local_test or not any(supplied)
                     else decrypt(*supplied))
    except (ValueError, ImportError, OSError, RuntimeError, KeyError,
            json.JSONDecodeError) as exc:
        parser.exit(1, "decryption failed: %s\n" % exc)
    sys.stdout.buffer.write(plaintext + b"\n")


if __name__ == "__main__":
    main()
