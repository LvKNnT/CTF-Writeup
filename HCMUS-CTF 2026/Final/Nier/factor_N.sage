import time
N = 20521461025340620036343427234076425700318756624055211212275291044020505897738976763
print(f"[*] factoring N ({N.nbits()} bits)...", flush=True)
t0 = time.time()
fac = factor(N)
print(f"[+] done in {time.time()-t0:.1f}s: {fac}", flush=True)
p, q = [pr for pr, _ in fac][:2]
print(f"p = {p}")
print(f"q = {q}")
print(f"p-1 factorization: {factor(p-1)}")
print(f"q-1 factorization: {factor(q-1)}")
