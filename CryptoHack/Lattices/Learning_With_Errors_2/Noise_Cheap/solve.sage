from pwn import *
from sage.all import *
import json

# Connection details
HOST = 'socket.cryptohack.org'
PORT = 13413

# Parameters
n = 64
p = 257
q = 1048583

def solve():
    # Connect to server
    r = remote(HOST, PORT)
    r.recvline() # Skip prompt

    print("[*] Collecting samples (encrypting m=0)...")
    
    # We need m > n samples. 80 is safe for n=64.
    num_samples = 80
    A_list = []
    b_list = []

    # 1. Collect samples
    for i in range(num_samples):
        req = {"option": "encrypt", "message": str(0)}
        r.sendline(json.dumps(req).encode())
        resp = json.loads(r.recvline().decode())
        
        A_list.append(json.loads(resp["A"]))
        b_list.append(int(resp["b"]))

    print("[*] Transforming samples (Modulus Inversion)...")
    
    # Calculate inverse of p mod q
    # We work in the field GF(q)
    F = GF(q)
    p_inv = F(p).inverse()
    
    # Transform b -> b' = b * p_inv
    # This turns (A*S + p*e) -> (A*S*p_inv + e)
    # Let S' = S * p_inv. Then b' = A*S' + e
    b_prime_list = [int(F(x) * p_inv) for x in b_list]

    # 2. Construct Lattice for LWE (Primal Attack)
    # We want to find the error vector e which is very short (-1, 0, 1)
    # Matrix format:
    # [ qI   0 ]
    # [ A^T  0 ]
    # [ b'   1 ]
    
    # Convert A to matrix
    A_mat = Matrix(ZZ, A_list)
    
    # Create Lattice Matrix
    # Dimensions: (num_samples + n + 1) x (num_samples + 1)
    L = Matrix(ZZ, num_samples + n + 1, num_samples + 1)
    
    # Fill q*I (top left)
    L.set_block(0, 0, q * identity_matrix(num_samples))
    
    # Fill A^T (middle left)
    L.set_block(num_samples, 0, A_mat.transpose())
    
    # Fill b' (bottom left)
    L[num_samples + n, :num_samples] = vector(ZZ, b_prime_list)
    
    # Fill 1 (bottom right)
    L[num_samples + n, num_samples] = 1

    print("[*] Running LLL lattice reduction...")
    L_reduced = L.LLL()

    # 3. Find the error vector
    e_vector = None
    for row in L_reduced:
        # We are looking for the row where the last element is 1 or -1
        if row[num_samples] == 1:
            potential_e = row[:num_samples]
            # Verify it's small
            if all(abs(x) <= 1 for x in potential_e):
                e_vector = potential_e
                break
        elif row[num_samples] == -1:
            potential_e = -row[:num_samples]
            if all(abs(x) <= 1 for x in potential_e):
                e_vector = potential_e
                break
    
    if e_vector is None:
        print("[-] Failed to recover error vector.")
        return

    print(f"[+] Error vector recovered: {e_vector[:5]}...")

    # 4. Recover S' and S
    # Equation: b' = A*S' + e  =>  A*S' = b' - e
    b_clean = vector(F, b_prime_list) - vector(F, e_vector)
    A_gf = Matrix(F, A_list)
    
    # Solve linear system for S'
    # We use solve_right (A * x = b)
    try:
        S_prime = A_gf.solve_right(b_clean)
        print("[+] S' recovered.")
    except ValueError:
        print("[-] Linear solve failed.")
        return

    # S = S' * p
    S = S_prime * F(p)
    print("[+] Secret Key S recovered.")

    # 5. Decrypt the Flag
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
        
        # Decryption:
        # b = A*S + m + p*e
        # diff = b - A*S = m + p*e
        
        diff = b_val - A_val.dot_product(S)
        
        # diff is (m + p*e) mod q.
        # Since e is small (-1, 0, 1) and m is small (0..256),
        # the integer value of diff will be close to 0 or close to q.
        # It's simplest to just try the 3 possibilities for e
        
        diff_int = int(diff)
        found_char = False
        
        # Try e = 0, 1, -1
        for e_guess in [0, 1, -1]:
            # m = diff - p*e
            m_candidate = (diff_int - p * e_guess) % q
            
            # Check if valid ascii/byte
            if 0 <= m_candidate < 256:
                flag += chr(m_candidate)
                found_char = True
                break
        
        if not found_char:
            flag += "?"
            
        print(f"\rFlag: {flag}", end="")
        index += 1

    print(f"\n[+] Full Flag: {flag}")
    r.close()

if __name__ == "__main__":
    solve()