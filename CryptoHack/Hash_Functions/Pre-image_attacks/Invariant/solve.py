#!/usr/bin/env python3
import itertools
import json
from hashlib import sha512
from pwn import *

# ==============================================================================
# 1. REPLICATE THE VULNERABLE CRYPTO SYSTEM LOCALLY
# ==============================================================================

class MyCipher:
    __NR = 31
    __SB = [13, 14, 0, 1, 5, 10, 7, 6, 11, 3, 9, 12, 15, 8, 2, 4]
    __SR = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

    def __init__(self, key):
        self.__RK = int(key.hex(), 16)
        self.__subkeys = [[(self.__RK >> (16 * j + i)) & 1 for i in range(16)]
                          for j in range(self.__NR + 1)]

    def __xorAll(self, v):
        res = 0
        for x in v:
            res ^= x
        return res

    def encrypt(self, plaintext):
        S = [int(_, 16) for _ in list(plaintext.hex())]
        for r in range(self.__NR):
            S = [S[i] ^ self.__subkeys[r][i] for i in range(16)]
            S = [self.__SB[S[self.__SR[i]]] for i in range(16)]
            X = [self.__xorAll(S[i:i + 4]) for i in range(0, 16, 4)]
            S = [X[c] ^ S[4 * c + r]
                 for c, r in itertools.product(range(4), range(4))]
        S = [S[i] ^ self.__subkeys[self.__NR][i] for i in range(16)]
        return bytes.fromhex("".join("{:x}".format(_) for _ in S))

class MyHash:
    def __init__(self, content):
        self.cipher = MyCipher(sha512(content).digest())
        self.h = b"\x00" * 8
        self._update(content)

    def _update(self, content):
        while len(content) % 8:
            content += b"\x00"
        for i in range(0, len(content), 8):
            self.h = bytes(x ^ y for x, y in zip(self.h, content[i:i+8]))
            self.h = self.cipher.encrypt(self.h)
            self.h = bytes(x ^ y for x, y in zip(self.h, content[i:i+8]))

    def digest(self):
        return self.h

# ==============================================================================
# 2. LOCAL BRUTE-FORCE IN THE INVARIANT SUBSPACE
# ==============================================================================

def find_collision():
    log.info("1-block subspace exhausted (37% chance of no fixed points).")
    log.info("Expanding to 16-byte (2-block) payloads...")
    
    target_hash = b"\x00" * 8
    allowed_bytes = [b'\x66', b'\x67', b'\x76', b'\x77']
    
    # Pre-compute all 65,536 valid 8-byte blocks for maximum speed
    log.info("Generating subspace blocks...")
    allowed_blocks = [b"".join(t) for t in itertools.product(allowed_bytes, repeat=8)]
    
    attempts = 0
    
    # Fix M1, and iterate all 65,536 possibilities for M2. 
    # If a specific M1 has no fixed points, move to the next M1.
    for m1 in allowed_blocks:
        log.info(f"Testing keyspace starting with M1 = {m1.hex()} ...")
        
        for m2 in allowed_blocks:
            payload = m1 + m2
            
            if MyHash(payload).digest() == target_hash:
                log.success(f"Collision found! Payload: {payload.hex()}")
                log.info(f"Total attempts: {attempts}")
                return payload.hex()
                
            attempts += 1
            if attempts % 10000 == 0:
                log.info(f"Tested {attempts} combinations...")
                
    log.error("Failed to find a collision even in 2-block space.")
    return None

# ==============================================================================
# 3. PWNTOOLS SERVER INTERACTION
# ==============================================================================

def main():
    # 1. Find the payload offline
    winning_payload = find_collision()
    
    # 2. Connect to the server
    # Note: Update HOST and PORT to match the actual challenge server if not running locally
    HOST = 'localhost' 
    PORT = 13393
    
    log.info(f"Connecting to challenge server at {HOST}:{PORT}")
    r = remote(HOST, PORT)
    
    # 3. Handle the server interaction
    # The server starts with a prompt
    r.recvline() 
    
    # Craft the JSON payload expected by the challenge
    req = json.dumps({
        "option": "hash",
        "data": winning_payload
    })
    
    # Send it off
    log.info(f"Sending JSON payload: {req}")
    r.sendline(req.encode())
    
    # Receive and parse the response
    response = r.recvline()
    result = json.loads(response.decode())
    
    log.info("Server Response:")
    if "flag" in result:
        log.success(f"FLAG: {result['flag']}")
    else:
        print(json.dumps(result, indent=4))
        
    r.close()

if __name__ == "__main__":
    main()