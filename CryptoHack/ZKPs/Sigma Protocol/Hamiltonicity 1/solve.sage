from sage.all import *
from pwn import remote
import glob
import importlib.util
import json
import os
import random
import sys

# bài này cũng là input/print thuần, sửa host/port cho khớp trang challenge nếu cần
HOST, PORT = "archive.cryptohack.org", 14635

# ---------------------------------------------------------------------------
# nạp file hamiltonicity_<hash>.py của challenge dưới tên module `hamiltonicity`
# để hàm hash Fiat-Shamir của ta khớp byte-for-byte với server
try:
    HERE = os.path.dirname(os.path.abspath(__file__))
except NameError:
    HERE = os.getcwd()

spec = importlib.util.spec_from_file_location(
    "hamiltonicity", glob.glob(os.path.join(HERE, "hamiltonicity*.py"))[0]
)
hamiltonicity = importlib.util.module_from_spec(spec)
sys.modules["hamiltonicity"] = hamiltonicity
spec.loader.exec_module(hamiltonicity)

from hamiltonicity import commit_to_graph, permute_graph, get_r_vals
from hamiltonicity import hash_committed_graph, comm_params

numrounds = 128
N = int(5)


def to_py(x):
    """.sage biến số nguyên thành Sage Integer, json.dumps không nuốt được -> ép về int."""
    if isinstance(x, (list, tuple)):
        return [to_py(i) for i in x]
    return int(x)


# Graph KHÔNG có hamiltonian cycle: 0->2->1->0 và 3<->4 là hai thành phần rời nhau
G = to_py([
    [0, 0, 1, 0, 0],
    [1, 0, 0, 0, 0],
    [0, 1, 0, 0, 0],
    [0, 0, 0, 0, 1],
    [0, 0, 0, 1, 0],
])

# Blum's hamiltonicity ZK, mỗi round prover commit ma trận kề đã hoán vị, verifier tung 1 bit:
#   bit 0 -> mở TOÀN BỘ, chứng minh đó đúng là G bị hoán vị  (làm được nếu commit thật từ G)
#   bit 1 -> mở N ô tạo thành cycle, tất cả phải mở ra 1      (làm được nếu commit từ đồ thị cycle)
# Prover thật làm được cả hai nên soundness error là 1/2 mỗi round.
#
# LỖ HỔNG: Fiat-Shamir ở đây lấy challenge = hash(A, state) mà A do CHÍNH TA gửi,
# nên ta tính trước được bit trước khi commit. Cứ chuẩn bị một A "kiểu 0" hoặc "kiểu 1",
# hash thử, cái nào ra đúng bit mà nó trả lời được thì gửi. Mỗi lần thử trúng ~1/2,
# grind vài nhịp là qua được cả 128 round dù G chẳng có cycle nào.


def gen_type0(FS_state):
    """commit thật từ G rồi hoán vị -> trả lời được bit 0."""
    A, openings = commit_to_graph(G, N)
    permutation = list(range(N))
    random.shuffle(permutation)
    A_permuted = permute_graph(A, N, permutation)
    z = [permutation, permute_graph(openings, N, permutation)]
    return A_permuted, z, hash_committed_graph(A_permuted, FS_state, comm_params)


def gen_type1(FS_state):
    """commit từ một đồ thị chỉ gồm đúng một hamiltonian cycle -> trả lời được bit 1."""
    permutation = list(range(N))
    random.shuffle(permutation)
    cycle = [[permutation[i], permutation[(i + 1) % N]] for i in range(N)]

    H = [[int(0)] * N for _ in range(N)]
    for src, dst in cycle:
        H[src][dst] = int(1)

    A, openings = commit_to_graph(H, N)
    z = [cycle, get_r_vals(openings, N, cycle)]
    return A, z, hash_committed_graph(A, FS_state, comm_params)


io = remote(HOST, PORT)
io.recvuntil(b"prove to me that G has a hamiltonian cycle!")

FS_state = b""
for i in range(numrounds):
    while True:
        A, z, state = gen_type0(FS_state)
        if state[-1] & 1 == 0:
            break
        A, z, state = gen_type1(FS_state)
        if state[-1] & 1 == 1:
            break

    FS_state = state
    io.recvuntil(b"send fiat shamir proof: ")
    io.sendline(json.dumps({"A": to_py(A), "z": to_py(z)}).encode())
    print(f"round {i}: bit {state[-1] & 1} -> {io.recvline().strip().decode()}")

io.interactive()
