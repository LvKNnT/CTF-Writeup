from pwn import *
from random import choice
from string import ascii_letters, digits
from Crypto.Util.number import isPrime
import numpy as np

# prod needs to be odd, so we'll discard characters with even ordinals
chrs = [ord(ch) for ch in (ascii_letters + digits) if ord(ch) % 2 == 1]

while True:
    # constant prefix satisfies complexity rules: 49, 65, 97 == chr('1'), chr('A'), chr('a')
    pw = [49, 65, 97] + [choice(chrs) for _ in range(20)]
    arr = np.array(pw)
    if isPrime(int(arr.sum())) and arr.sum() == np.prod(arr):
        break
        
# search completes in ~100 ms
password = ''.join(chr(b) for b in pw)
print("Password:", password)
print("Submitting...")

io = remote("socket.cryptohack.org", 13401)
io.recvline()
io.send(f'{{"password": "{password}"}}'.encode())
print(io.recvline().decode())