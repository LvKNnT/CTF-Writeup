from pwn import *
import json
from collections import Counter

# Connection details
HOST = 'socket.cryptohack.org'
PORT = 13390
q = 127

def solve():
    # Connect to the server
    r = remote(HOST, PORT)
    r.recvline() # Skip welcome message

    print("[*] Collecting samples (Differential Attack)...")
    
    samples = []
    # We need enough samples to ensure every index is modified at least once.
    # Coupon collector problem suggests ~200 samples is plenty for length ~30.
    NUM_SAMPLES = 300 
    
    for i in range(NUM_SAMPLES):
        # 1. Reset to force the same base 'a' and 'e'
        r.sendline(json.dumps({"option": "reset"}).encode())
        r.recvline() # Skip success message
        
        # 2. Get the sample (which might be faulty)
        r.sendline(json.dumps({"option": "get_sample"}).encode())
        resp = json.loads(r.recvline().decode())
        samples.append(resp)

    # --- Step 1: Identify the Base (Unmodified) Sample ---
    # The unmodified sample appears ~50% of the time. It is the mode.
    # We serialize the list 'a' to tuple to make it hashable for Counter
    a_counts = Counter(tuple(s['a']) for s in samples)
    base_a_tuple = a_counts.most_common(1)[0][0]
    base_a = list(base_a_tuple)
    
    # Find the corresponding b for this base_a
    # (Just take the first sample that matches base_a)
    base_b = next(s['b'] for s in samples if tuple(s['a']) == base_a_tuple)
    
    print(f"[+] Identified base vector length: {len(base_a)}")

    # --- Step 2: Calculate Flag Characters from Differences ---
    flag_chars = [None] * len(base_a)
    
    for s in samples:
        a_curr = s['a']
        b_curr = s['b']
        
        # Skip if this is the base sample (no difference)
        if a_curr == base_a:
            continue
            
        # Find the index where they differ
        # There should be exactly one difference according to source code
        diff_indices = [i for i in range(len(base_a)) if a_curr[i] != base_a[i]]
        
        if len(diff_indices) != 1:
            continue # Should not happen based on challenge logic, but good safety
            
        k = diff_indices[0]
        
        if flag_chars[k] is not None:
            continue # Already solved this char
            
        # Math:
        # delta_b = delta_a * flag[k]  (mod q)
        # flag[k] = delta_b * inverse(delta_a) (mod q)
        
        delta_a = (a_curr[k] - base_a[k]) % q
        delta_b = (b_curr - base_b) % q
        
        try:
            inv_a = pow(delta_a, -1, q)
            flag_val = (delta_b * inv_a) % q
            flag_chars[k] = flag_val
        except ValueError:
            # Inverse doesn't exist (delta_a is 0), skip
            pass

    # --- Step 3: Reconstruction ---
    # Convert integers back to bytes
    try:
        # Filter out None if any indices weren't hit (unlikely with 300 samples)
        res = "".join(chr(c) if c is not None else "?" for c in flag_chars)
        print(f"[+] Flag: {res}")
    except Exception as e:
        print(f"[-] Error decoding flag: {e}")
        print("Raw values:", flag_chars)
    
    r.close()

if __name__ == "__main__":
    solve()