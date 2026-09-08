import json
from pwn import remote

# Target configuration
HOST = 'socket.cryptohack.org'
PORT = 13418

# Composite Modulus Factors
p = 4782850957738000717885060297350722702854694354378697989111
q = 4796464665474109238546017500238174976861701183900526078141
modulus = p * q

a = -3
b = 2697448053935541741976221051345108825177671050689533270507
order = 4782850957738000717885060297297408935631027604045525430677

def get_twist_point(F_prime):
    """Finds an x-coordinate that is a quadratic non-residue (forces the twist)."""
    x_val = F_prime(1)
    while True:
        rhs = x_val^3 + a*x_val + b
        if not rhs.is_square():
            return x_val, rhs
        x_val += 1

def solve_subgroups(E_prime, P, Q, N, limit_bits=45):
    """Factors the twist order and solves DLP for small smooth subgroups."""
    print(f"[*] Factoring twist order...")
    factors = []
    
    # We only care about highly smooth factors
    for p_fac, e in factor(N):
        if p_fac < 2^limit_bits:
            factors.append((p_fac, e))
            
    dlogs = []
    moduli = []
    
    for p_fac, e in factors:
        sub_order = p_fac^e
        cofactor = N // sub_order
        
        P_sub = cofactor * P
        Q_sub = cofactor * Q
        
        try:
            dl = discrete_log(Q_sub, P_sub, operation='+')
            dlogs.append(dl)
            moduli.append(sub_order)
            print(f"    -> Solved modulo {p_fac}^{e}: {dl}")
        except Exception as e:
            print(f"    [-] Failed DL in subgroup {p_fac}^{e}")
            
    return dlogs, moduli

def solve():
    Fp = GF(p)
    Fq = GF(q)
    
    print("[*] Finding non-residues for Fp and Fq...")
    xp, cp = get_twist_point(Fp)
    xq, cq = get_twist_point(Fq)
    
    # Use CRT to combine xp and xq into our malicious x0
    x0_int = int(crt([int(xp), int(xq)], [p, q]))
    print(f"[+] Crafted CRT x0 = {x0_int}")

    print(f"[*] Connecting to {HOST}:{PORT}...")
    import logging
    logging.getLogger("pwnlib").setLevel(logging.ERROR)
    
    r = remote(HOST, PORT)
    r.recvuntil(b"decimal format.\n")
    
    # 1. Send the malicious x0
    req = json.dumps({"option": "get_pubkey", "x0": str(x0_int)})
    r.sendline(req.encode())
    
    res = json.loads(r.recvline().decode())
    if "error" in res:
        print("[-] Error from server:", res["error"])
        return
        
    pub_x = int(res['pubkey'])
    print(f"[+] Received public key x-coordinate = {pub_x}")

    all_dlogs = []
    all_moduli = []

    # --- Process Modulo p ---
    print("\n--- Processing Twist Modulo p ---")
    Ep_twist = EllipticCurve(Fp, [a * cp^2, b * cp^3])
    P_p = Ep_twist(xp * cp, cp^2)
    Q_p = Ep_twist.lift_x(Fp(pub_x) * cp)
    Np = Ep_twist.order()
    
    dlogs_p, moduli_p = solve_subgroups(Ep_twist, P_p, Q_p, Np)
    all_dlogs.extend(dlogs_p)
    all_moduli.extend(moduli_p)

    # --- Process Modulo q ---
    print("\n--- Processing Twist Modulo q ---")
    Eq_twist = EllipticCurve(Fq, [a * cq^2, b * cq^3])
    P_q = Eq_twist(xq * cq, cq^2)
    Q_q = Eq_twist.lift_x(Fq(pub_x) * cq)
    Nq = Eq_twist.order()
    
    dlogs_q, moduli_q = solve_subgroups(Eq_twist, P_q, Q_q, Nq)
    all_dlogs.extend(dlogs_q)
    all_moduli.extend(moduli_q)

    # --- Combine with CRT ---
    print("\n[*] Combining all subgroups using CRT...")
    current_prod = prod(all_moduli)
    print(f"[*] Total smooth product size: ~{float(log(current_prod, 2)):.2f} bits (Need > 192)")
    
    if current_prod < 2^192:
        print("[-] Error: Not enough smooth factors recovered to span the 192-bit key.")
        return

    recovered_k = crt(all_dlogs, all_moduli)
    
    # Resolve the sign ambiguity
    k_candidate_1 = int(recovered_k)
    k_candidate_2 = int(current_prod - recovered_k)
    
    privkey = min(k_candidate_1, k_candidate_2)
    print(f"[+] Recovered Private Key Candidate: {privkey}")
    
    # 2. Submit the recovered private key
    req2 = json.dumps({"option": "get_flag", "privkey": privkey})
    r.sendline(req2.encode())
    
    flag_res = json.loads(r.recvline().decode())
    if "flag" in flag_res:
        print(f"\n[+] SUCCESS! Flag: {flag_res['flag']}")
    else:
        print(f"\n[-] Failed. Server returned: {flag_res}")
        
    r.close()

if __name__ == "__main__":
    solve()