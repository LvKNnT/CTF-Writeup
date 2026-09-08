from Crypto.Util.number import *
from gmpy2 import *
import math
# from pwn import *   
from tqdm import tqdm
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import md5
import json
import time
from Crypto.Hash import SHA256
import os
import random
import os
import Crypto.Util.number as cun
from hashlib import sha512
from sympy.ntheory.residue_ntheory import discrete_log

from output import data

def decrypt_flag(iv,ct,secret):
    key = SHA256.new(int.to_bytes(int(secret), 8,'big')).digest()[:128]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    flag = cipher.decrypt(ct)

    return flag

def compute_supersingular_delta(E_0, E_test):
    Fp.<x> = PolynomialRing(E_0.base_field())
    a = E_0.a4()
    r = (x^3 + a * x + E_0.a6()).roots()[0][0]
    riso = (x^3 + E_test.a4() * x + E_test.a6()).roots()[0][0]

    char = ((E_test.a4() + 3*riso^2)/(a + 3*r^2))^((p - 1) / 4)
    return 1 if char == 1 else -1

ls = list(primes(3, 112)) + [139]
p = 2 * prod(ls) - 1
max_exp = ceil((sqrt(p) ** (1 / len(ls)) - 1) / 2)
Fp2 = GF(p**2, names="w", modulus=[3, 0, 1])
w = Fp2.gen()
base = EllipticCurve(Fp2, [0, 1])

iv = bytes.fromhex(data['iv'])
ct = bytes.fromhex(data['ct'])

challenge_data = data['challenge_data']

key = ""
for i in tqdm(range(len(challenge_data))):
    EA = challenge_data[i]['EA']
    a4_EA,a6_EA = EA['a4'][0],EA['a6'][0]
    EA = EllipticCurve(Fp2, [a4_EA, a6_EA])
    
    EB = challenge_data[i]['EB']
    a4_EB,a6_EB = EB['a4'][0],EB['a6'][0]
    EB = EllipticCurve(Fp2, [a4_EB, a6_EB])
    
    EC = challenge_data[i]['EC']
    a4_EC,a6_EC = EC['a4'][0],EC['a6'][0]
    EC = EllipticCurve(Fp2, [a4_EC, a6_EC])
    
    if compute_supersingular_delta(base,EA) == compute_supersingular_delta(EB,EC):
        key += "1"
    else:
        key += "0"

secret = int(key[::-1],2)
flag = decrypt_flag(iv,ct,secret)
print(flag)
