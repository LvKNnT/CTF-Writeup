from sage.all import *
from pwn import *
import json

# Connection details
HOST = 'socket.cryptohack.org' # Replace with actual host if different
PORT = 13411

# Challenge parameters
n = 64
q = 0x10001
F = GF(q)

def solve():
    # Connect to the server
    r = remote(HOST, PORT)
    
    # Receive initial prompt
    r.recvline()

    print("[*] Collecting 64 equations to recover Secret Key S...")
    
    A_list = []
    b_list = []

    # Phase 1: Recover S
    # We need 64 equations. We encrypt m=0 so b = A*S
    for i in range(n):
        req = {"option": "encrypt", "message": str(0)}
        r.sendline(json.dumps(req).encode())
        
        resp = json.loads(r.recvline().decode())
        
        # Parse A (string representation of list) and b
        A_val = json.loads(resp["A"])
        b_val = int(resp["b"])
        
        A_list.append(A_val)
        b_list.append(b_val)

    # Construct Matrix and Vector over Finite Field
    M = Matrix(F, A_list)
    v_b = vector(F, b_list)

    # Solve for S: M * S = v_b  =>  S = M^(-1) * v_b
    # solve_right handles the linear algebra equation M * x = b
    try:
        S = M.solve_right(v_b)
        print("[+] Secret Key S recovered!")
    except ValueError:
        print("[-] Matrix was not invertible. Try running again.")
        return

    # Phase 2: Decrypt the flag
    print("[*] Decrypting flag...")
    
    flag = ""
    index = 0
    
    while True:
        req = {"option": "get_flag", "index": str(index)}
        r.sendline(json.dumps(req).encode())
        
        line = r.recvline().decode()
        if "error" in line:
            break
            
        resp = json.loads(line)
        
        A_val = vector(F, json.loads(resp["A"]))
        b_val = F(int(resp["b"]))
        
        # Decrypt: m = b - A*S
        # dot_product returns a field element, we cast to int
        m = b_val - A_val.dot_product(S)
        
        flag += chr(int(m))
        print(f"\rFlag so far: {flag}", end="")
        index += 1

    print(f"\n[+] Full Flag: {flag}")
    r.close()

if __name__ == "__main__":
    solve()