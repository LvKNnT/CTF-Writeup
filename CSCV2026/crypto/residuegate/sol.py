#!/usr/bin/env python3
import hashlib, io, json, os, struct, time, urllib.error, urllib.request
import numpy as np
from PIL import Image

ENDPOINT = os.environ.get("RESIDUEGATE_ENDPOINT", "http://127.0.0.1:5000").rstrip("/")
MODEL_DIR = os.environ.get("RESIDUEGATE_MODEL_DIR", "qwen3vl2b")
PACE = 1.6
ROUTES = {
    "session": "/feature_fa8688cbfa3fc935ae60de224a972126",
    "public": "/feature_a9e63777c9a2409902b702d5238a61b8",
    "slot": "/feature_c426f4d0ed166214ae89992cbd592932",
    "evalenc": "/feature_11edaf0d1c4e447615614810348a3030",
    "upload": "/feature_c26f994e7f7d755a4602972a35430050",
}
N = 64
P1, P2 = 65537, 3
T = P1 * P2
MUL = P1 + 1  # == 1 mod p1, == 0 mod p2: message rides p1
DOMAIN = b"residuegate-six-way-logit-commitment-v1\x00"
QUADRANTS = [(0, 0), (0, 16), (16, 0), (16, 16)]
BOUNDARY = "----residuegate7f3a9c1e"


def req(url, data=None, headers=None, method=None, timeout=90):
    r = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            out = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        out = e.code, e.read()
    time.sleep(PACE)
    return out


def centre(v, m):
    v %= m
    return v - m if v > m // 2 else v


# --------------------------------------------------------------- ring, key, crypto


def mulmat(a, q):
    """Negacyclic multiplication matrix of a in Z_q[x]/(x^64+1)."""
    M = [[0] * N for _ in range(N)]
    for k in range(N):
        for j in range(N):
            i = k - j
            M[k][j] = a[i] % q if i >= 0 else (-a[i + N]) % q
    return M


def polymul(x, y, q):
    out = [0] * N
    for i, xi in enumerate(x):
        if not xi:
            continue
        for j, yj in enumerate(y):
            if not yj:
                continue
            k, v = i + j, xi * yj
            if k >= N:
                k, v = k - N, -v
            out[k] = (out[k] + v) % q
    return out


def gauss(M, rhs, q, unknowns, exact=False):
    """Gaussian elimination over Z_q.  exact=True requires full rank + consistency."""
    A = [row[:] + [rhs[i] % q] for i, row in enumerate(M)]
    pivots, row = [], 0
    for col in range(unknowns):
        piv = next((r for r in range(row, len(A)) if A[r][col] % q), None)
        if piv is None:
            continue
        A[row], A[piv] = A[piv], A[row]
        inv = pow(A[row][col], -1, q)
        A[row] = [v * inv % q for v in A[row]]
        for r in range(len(A)):
            if r != row and A[r][col] % q:
                f = A[r][col]
                A[r] = [(A[r][c] - f * A[row][c]) % q for c in range(unknowns + 1)]
        pivots.append(col)
        row += 1
    if exact:
        assert len(pivots) == unknowns, "rank-deficient system"
        for r in range(row, len(A)):
            assert A[r][unknowns] % q == 0, "plaintext outside the packing image"
    sol = [0] * unknowns
    for i, col in enumerate(pivots):
        sol[col] = A[i][unknowns] % q
    return sol


def encrypt_u1(m, pk_b, pk_na, q):
    """u = 1.  Decryption is exact, so b = a*s and dec = (b - a*s) + encode(m)."""
    t = (m % P1) * MUL % T
    if t >= (T + 1) // 2:
        t -= T
    return {"c0": [(pk_b[i] + (t if i == 0 else 0)) % q for i in range(N)], "c1": [c % q for c in pk_na]}


# ------------------------------------------------------------------ packed decode


def _trim(p):
    while p and p[-1] == 0:
        p.pop()
    return p


def _polyrem(f, g, q):
    f, g = _trim([v % q for v in f]), _trim([v % q for v in g])
    inv = pow(g[-1], -1, q)
    while len(f) >= len(g) and f:
        shift, c = len(f) - len(g), f[-1] * inv % q
        for i, gi in enumerate(g):
            f[shift + i] = (f[shift + i] - c * gi) % q
        _trim(f)
    return f


def packing_columns(neg_a, q):
    """H = monic gcd(a, x^64+1) has degree 32, so R_q splits and one reply packs
    all four logits: P = p0*H + p1*x*H + p2*H(-x) + p3*x*H(-x)."""
    f, g = [(-v) % q for v in neg_a], [1] + [0] * (N - 1) + [1]
    while g:
        f, g = g, _polyrem(f, g, q)
    inv = pow(f[-1], -1, q)
    H = [v * inv % q for v in f]
    assert len(H) == 33, "gcd(a, x^64+1) has degree %d, expected 32" % (len(H) - 1)
    Hneg = [(-v if i % 2 else v) % q for i, v in enumerate(H)]
    cols = []
    for base in (H, Hneg):
        for shift in (0, 1):
            col = [0] * N
            for i, v in enumerate(base):
                col[i + shift] = v
            cols.append(col)
    return cols


def logits_from_reply(packed, s, sess):
    cr = sess["crypto"]
    q, p1 = cr["q"], cr["p1"]
    prod = polymul(packed["c1"], s, q)
    P = [centre(packed["c0"][i] + prod[i], q) for i in range(N)]
    cols = packing_columns(cr["public_key"]["neg_a"], q)
    B = [[cols[c][i] for c in range(4)] for i in range(N)]
    # centre mod q FIRST, then reduce mod p1 - the other order adds a multiple of
    # q mod p1 and makes deterministic values look like a per-session mask
    mixed = [centre(centre(v, q), p1) for v in gauss(B, P, q, 4, exact=True)]
    return [centre(v, p1) for v in gauss(sess["mixing_matrix"], mixed, p1, 4, exact=True)]


# ------------------------------------------------------------------ badge images


def apply_variant(base_rgb, variant, eps=8):
    out = base_rgb.astype(np.int16).copy()
    for qi, (r0, c0) in enumerate(QUADRANTS):
        for ch in range(3):
            column = 3 * qi + ch + 1
            sign = 1 if bin(variant & column).count("1") % 2 == 0 else -1
            out[r0 : r0 + 16, c0 : c0 + 16, ch] += eps * sign
    return out


def png_bytes(arr):
    assert arr.min() >= 0 and arr.max() <= 255, "variant would clip"
    buf = io.BytesIO()
    Image.fromarray(arr.astype(np.uint8), mode="RGB").save(buf, format="PNG")
    return buf.getvalue()


# ------------------------------------------------------------------- commitment


def find_tuple(commitment_hex, seed_hex, logits_by_slot):
    """Depth-first over the six slots, reusing partial SHA-256 states."""
    target = bytes.fromhex(commitment_hex)
    blocks = [
        [
            struct.pack("<BB", s, v) + b"".join(struct.pack("<q", int(x)) for x in logits_by_slot[s][v])
            for v in range(16)
        ]
        for s in range(6)
    ]

    def rec(slot, h, acc):
        if slot == 6:
            return tuple(acc) if h.digest() == target else None
        for v in range(16):
            h2 = h.copy()
            h2.update(blocks[slot][v])
            got = rec(slot + 1, h2, acc + [v])
            if got:
                return got
        return None

    return rec(0, hashlib.sha256(DOMAIN + bytes.fromhex(seed_hex)), [])


# -------------------------------------------------------------------- embeddings


def embed(images_u8, vcfg):
    """The published pipeline: bicubic 448, vision tower, mean-pool, signed random
    projection, quantise."""
    import torch
    from transformers import AutoConfig, AutoProcessor
    from transformers.models.qwen3_vl.modeling_qwen3_vl import Qwen3VLVisionModel
    from safetensors import safe_open

    torch.use_deterministic_algorithms(True)

    cfg = AutoConfig.from_pretrained(MODEL_DIR, local_files_only=True).vision_config
    cfg._attn_implementation = "eager"
    model = Qwen3VLVisionModel(cfg)
    loaded = False
    with safe_open(f"{MODEL_DIR}/model.safetensors", framework="pt", device="cpu") as sd:
        keys = sd.keys()
        for prefix in ("model.visual.", "visual."):
            matched = [k for k in keys if k.startswith(prefix)]
            if matched:
                vis = {k[len(prefix) :]: sd.get_tensor(k) for k in matched}
                model.load_state_dict(vis, strict=False)
                del vis
                loaded = True
                break
    if not loaded:
        raise RuntimeError("model.safetensors contains no recognized Qwen vision weights")
    model = model.to(torch.float32).eval()
    proc = AutoProcessor.from_pretrained(MODEL_DIR, local_files_only=True)

    merge = model.spatial_merge_size**2
    pooled = []
    batch_size = int(os.environ.get("RESIDUEGATE_EMBED_BATCH_SIZE", "2"))
    for i in range(0, len(images_u8), batch_size):
        print("vision embeddings %d/%d" % (i, len(images_u8)), flush=True)
        pil = [Image.fromarray(a, mode="RGB").resize((448, 448), Image.BICUBIC) for a in images_u8[i : i + batch_size]]
        inp = proc.image_processor(images=pil, return_tensors="pt")
        thw = inp["image_grid_thw"]
        with torch.no_grad():
            res = model(inp["pixel_values"].to(torch.float32), grid_thw=thw)
        hs = res[0] if isinstance(res, (tuple, list)) else getattr(res, "last_hidden_state", res)
        pos = 0
        for n in (thw.prod(-1) // merge).tolist():
            pooled.append(hs[pos : pos + n].to(torch.float32).mean(dim=0).numpy())
            pos += n
    pooled = np.stack(pooled)

    bits = np.random.Generator(np.random.PCG64(vcfg["projection_seed"])).integers(
        0, 2, size=(vcfg["embedding_dimension"], vcfg["feature_dimension"]), dtype=np.int8
    )
    Pm = (bits.astype(np.float32) * 2.0 - 1.0) / np.sqrt(vcfg["feature_dimension"])
    projd = pooled.astype(np.float32) @ Pm.T
    lo, hi = vcfg["quantized_range"]
    return np.clip(
        np.rint(
            (projd - np.asarray(vcfg["projection_center"], np.float32))
            / np.asarray(vcfg["projection_scale"], np.float32)
            * vcfg["quantization_gain"]
        ),
        lo,
        hi,
    ).astype(np.int8)


# -------------------------------------------------------------------------- main


def main():
    st, body = req(ENDPOINT + ROUTES["session"], data=b"", method="POST")
    assert st == 200, (st, body[:200])
    sess = json.loads(body)
    sid, cr = sess["session_id"], sess["crypto"]
    q, pk_b, pk_na = cr["q"], cr["public_key"]["b"], cr["public_key"]["neg_a"]
    s = gauss(mulmat([(-v) % q for v in pk_na], q), pk_b, q, N)
    print("session", sid)

    seq = [0]

    def logits_for(vec):
        seq[0] += 1
        st, r = req(
            ENDPOINT + ROUTES["evalenc"],
            data=json.dumps(
                {"session_id": sid, "sequence": seq[0], "embedding": [encrypt_u1(m, pk_b, pk_na, q) for m in vec]}
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert st == 200, (st, r[:300])
        return logits_from_reply(json.loads(r)["packed_logits"], s, sess)

    bias = np.array(logits_for([0] * 12))
    W = np.array([logits_for([1 if i == j else 0 for i in range(12)]) for j in range(12)]).T - bias[:, None]
    chk = np.random.default_rng(1).integers(-16, 17, 12)
    assert logits_for(chk.tolist()) == (W @ chk + bias).tolist(), "head self-check failed"

    bases = []
    for slot in range(6):
        st, pb = req(f"{ENDPOINT}{ROUTES['slot']}?slot={slot}&session_id={sid}")
        assert st == 200, (st, pb[:200])
        bases.append(np.array(Image.open(io.BytesIO(pb)).convert("RGB")))

    vcfg = json.loads(json.loads(req(ENDPOINT + ROUTES["public"])[1])["vision_config_json"])
    variants = [[apply_variant(bases[sl], v) for v in range(16)] for sl in range(6)]
    t0 = time.time()
    q12 = embed([variants[sl][v].astype(np.uint8) for sl in range(6) for v in range(16)], vcfg)
    print("96 embeddings in %.0fs" % (time.time() - t0))

    by_slot = [[(W @ q12[sl * 16 + v].astype(int) + bias).tolist() for v in range(16)] for sl in range(6)]
    tup = find_tuple(sess["combination"]["commitment"], sess["combination"]["seed"], by_slot)
    assert tup, "no tuple matched the commitment - not submitting"
    print("tuple", tup)

    parts = b""
    for sl in range(6):
        parts += f"--{BOUNDARY}\r\n".encode()
        parts += (f'Content-Disposition: form-data; name="image_{sl}"; filename="image_{sl}.png"\r\n').encode()
        parts += b"Content-Type: image/png\r\n\r\n" + png_bytes(variants[sl][tup[sl]]) + b"\r\n"
    parts += f"--{BOUNDARY}\r\n".encode()
    parts += b'Content-Disposition: form-data; name="session_id"\r\n\r\n' + sid.encode() + b"\r\n"
    parts += f"--{BOUNDARY}--\r\n".encode()
    st, resp = req(
        ENDPOINT + ROUTES["upload"],
        data=parts,
        method="POST",
        timeout=180,
        headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"},
    )
    print(resp.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
