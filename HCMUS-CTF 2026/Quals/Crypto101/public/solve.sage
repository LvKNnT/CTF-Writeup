#!/usr/bin/env sage

import ast
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def main():
    print("[*] Loading data from output.txt...")
    try:
        with open("output.txt", "r") as f:
            lines = f.read().strip().split('\n')
    except FileNotFoundError:
        print("[-] output.txt not found! Please run 'nc chall.blackpinker.com 20799 > output.txt' first.")
        return
        
    Px_mod_p = int(lines[0])
    R = ast.literal_eval(lines[1])
    ct_hex = lines[-1]

    print("[*] Recovering the hidden prime p via GCD...")
    v = [(R[i][1]**2 - R[i][0]**3) for i in range(len(R))]
    g = 0
    for i in range(2, min(20, len(R))):
        t = (v[0] - v[1]) * (R[0][0] - R[i][0]) - (v[0] - v[i]) * (R[0][0] - R[1][0])
        g = gcd(g, t)
        if g > 0 and g.nbits() < 1050: 
            break

    p = None
    for k in range(1, 100000):
        if g % k == 0:
            cand_p4 = g // k
            cand_p = ZZ(cand_p4).isqrt().isqrt()
            if cand_p**4 == cand_p4 and cand_p.is_prime():
                p = cand_p
                break

    if p is None:
        print("[-] Failed to recover p.")
        return

    print(f"[+] Recovered 256-bit prime p: {p}")
    mod = p**4

    print("[*] Recovering curve parameters a and b...")
    a, b = None, None
    for i in range(len(R)):
        for j in range(i + 1, len(R)):
            try:
                inv = inverse_mod(R[i][0] - R[j][0], mod)
                a = ((R[i][1]**2 - R[j][1]**2) - (R[i][0]**3 - R[j][0]**3)) * inv % mod
                b = (R[i][1]**2 - R[i][0]**3 - a*R[i][0]) % mod
                break
            except ZeroDivisionError:
                continue
        if a is not None:
            break

    print("[*] Calculating curve order over GF(p)...")
    Ep = EllipticCurve(GF(p), [a % p, b % p])
    N = Ep.order()
    M = N * (p**3)

    print("[*] Lifting to p-adic logarithms...")
    E4 = EllipticCurve(Zmod(mod), [a, b])
    z_list = []

    for j in range(120):
        P1 = E4(R[j][0], R[j][1])
        P2 = P1 * (N - 1)
        x1, y1 = ZZ(P2[0]), ZZ(P2[1])
        x2, y2 = ZZ(P1[0]), ZZ(P1[1])

        A = (x2 - x1) % mod
        B = (y2 - y1) % mod
        num_x = (B**2 - A**2 * (x1 + x2)) % mod
        
        num_X = (A * num_x) % mod
        num_Y = (B * (A**2 * x1 - num_x) - A**3 * y1) % mod
        
        t = (-num_X * inverse_mod(num_Y, mod)) % mod
        z_list.append((t // p) % (p**3))

    print("[*] Setting up LLL to find exact relations...")
    K = 2**1000  
    L = matrix(ZZ, 121, 121)
    for i in range(120):
        L[i, i] = 1
        L[i, 120] = K * z_list[i]
    L[120, 120] = K * (p**3)

    print("[*] Running LLL (this might take a few seconds)...")
    L_red = L.LLL()

    print("[*] Filtering exactly the structural relations...")
    V_rows = [list(r[:120]) for r in L_red if r[120] == 0 and vector(r[:120]).norm() < 1000]
    print(f"[*] Extracted {len(V_rows)} structural nullspace relations.")
    
    V = matrix(ZZ, V_rows)
    B_basis = V.right_kernel_matrix()
    
    print("[*] Running MILP to recover the hidden matrix C...")
    columns_of_C = set()
    import random
    
    for _ in range(500):
        if len(columns_of_C) >= 24:
            break
            
        p_milp = MixedIntegerLinearProgram(maximization=True, solver='GLPK')
        u = p_milp.new_variable(integer=True)
        
        x = []
        active_indices = []
        for j in range(120):
            # Fix: Safely verify if a column is all zeros to prevent Sage TypeError
            is_zero_col = all(B_basis[i, j] == 0 for i in range(B_basis.nrows()))
            
            if is_zero_col:
                x.append(0)
            else:
                expr = sum(u[i] * B_basis[i, j] for i in range(B_basis.nrows()))
                x.append(expr)
                active_indices.append(j)
                p_milp.add_constraint(expr >= 0)
                p_milp.add_constraint(expr <= 255)
            
        obj = sum(random.randint(-100, 100) * x[j] for j in active_indices)
        p_milp.set_objective(obj)
        
        try:
            p_milp.solve()
            res = []
            for j in range(120):
                if j not in active_indices:
                    res.append(0)
                else:
                    res.append(int(round(p_milp.get_values(x[j]))))
            res = tuple(res)
            if any(v != 0 for v in res):
                columns_of_C.add(res)
        except Exception:
            pass

    columns_of_C = list(columns_of_C)
    print(f"[*] Recovered {len(columns_of_C)}/24 columns of C.")

    print("[*] Solving for linear combination mapping R_j -> S...")
    C_T = matrix(QQ, columns_of_C)
    target = vector(QQ, [1] * 24)
    x_sol = C_T.solve_right(target)

    D = lcm([val.denominator() for val in x_sol])
    x_int = [val * D for val in x_sol]

    print("[*] Aggregating points on the curve...")
    S_scaled = E4(0, 1, 0)
    for j in range(120):
        if x_int[j] != 0:
            P_j = E4(R[j][0], R[j][1])
            if x_int[j] > 0:
                S_scaled += P_j * int(x_int[j])
            else:
                S_scaled -= P_j * int(-x_int[j])

    print("[*] Multiplying by modular inverse of D...")
    D_inv = inverse_mod(int(D), int(M))
    S = S_scaled * D_inv

    print("[*] Decrypting flag...")
    key = md5(str(S).encode()).digest()
    aes = AES.new(key=key, mode=AES.MODE_ECB)
    
    try:
        flag = unpad(aes.decrypt(bytes.fromhex(ct_hex)), 16)
        print(f"\n[+] FLAG: {flag.decode()}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")

if __name__ == "__main__":
    main()