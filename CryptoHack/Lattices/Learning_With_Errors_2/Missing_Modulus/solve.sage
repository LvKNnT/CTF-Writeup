from pwn import *
import json
import numpy as np

# Connection details
HOST = 'socket.cryptohack.org'
PORT = 13412

# Parameters
n = 512
p = 257
q = 6007
delta = int(round(q/p))

def solve():
    # Connect
    r = remote(HOST, PORT)
    r.recvline() # Skip initial prompt

    print("[*] Collecting samples for Linear Regression...")
    
    num_samples = 550
    A_list = []
    b_list = []

    for i in range(num_samples):
        req = {"option": "encrypt", "message": str(0)}
        r.sendline(json.dumps(req).encode())
        
        resp = json.loads(r.recvline().decode())
        
        # --- FIX IS HERE ---
        # The server returns strings: "A": "[...]", "b": "..."
        # We must parse them into lists and ints.
        A_list.append(json.loads(resp["A"]))
        b_list.append(int(resp["b"]))
        # -------------------
        
        if i % 50 == 0:
            print(f"    Collected {i}/{num_samples} samples...")

    # Convert to numpy arrays
    print("[*] Solving linear system (Least Squares)...")
    Matrix_A = np.array(A_list, dtype=np.float64)
    Vector_b = np.array(b_list, dtype=np.float64)

    # Solve S = (A^T * A)^-1 * A^T * b
    S_est, residuals, rank, s = np.linalg.lstsq(Matrix_A, Vector_b, rcond=None)
    
    # Round to nearest integer to get the exact Secret Key
    S = np.round(S_est).astype(np.int64)
    print("[+] Secret Key S recovered.")

    # --- Decrypt the Flag ---
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
        # Parse here as well!
        A_val = np.array(json.loads(resp["A"]), dtype=np.int64)
        b_val = int(resp["b"])
        
        # Decryption Logic:
        # m = (b - A*S) / delta
        noise_message = b_val - np.dot(A_val, S)
        m = int(round(noise_message / delta))
        
        flag += chr(m)
        print(f"\rFlag so far: {flag}", end="")
        index += 1
        
    print(f"\n[+] Full Flag: {flag}")
    r.close()

if __name__ == "__main__":
    solve()