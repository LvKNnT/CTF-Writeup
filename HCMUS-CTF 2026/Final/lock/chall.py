from Crypto.Util.number import getPrime, isPrime, bytes_to_long
import hashlib
from math import gcd
import os

def hash_to_prime(g, y, T):
    h = hashlib.sha256(f"{g}_{y}_{T}".encode()).digest()
    p = bytes_to_long(h)
    while not isPrime(p):
        p += 1
    return p

def is_inside(p, n):
    assert gcd(p, n) == 1
    return 1 < p < n - 1

if __name__ == "__main__":
    p = getPrime(128)
    q = getPrime(128)
    N = p * q
    g = getPrime(256)
    
    print(f"g = {g}")

    y = int(input("y: ")) % N
    if not is_inside(y, N):
        exit()
    
    print(f"N = {N}") 
    
    logT = int(input("logT: "))
    if logT < 50:
        exit()
    T = 2 ** logT
        
    pi = int(input("pi: ")) % N
    if not is_inside(pi, N):
        exit()

    print("Verifying Wesolowski Proof...")
    
    l = hash_to_prime(g, y, T)
    r = pow(2, T, l)
    
    lhs = (pow(pi, l, N) * pow(g, r, N)) % N
    
    if lhs == y:
        try:
            with open("flag.txt", "r") as f:
                print(f.read())
        except FileNotFoundError:
            print("flag{redacted}")
    else:
        print("Not a Time traveler?")
