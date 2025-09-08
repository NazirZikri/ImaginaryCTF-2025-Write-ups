zkPoW (Crypto / Pwn hybrid) Solution
Challenge description (paraphrased):
Designed a new way to stop brute-forcing pwn challenges: a “zk-proof-of-work.”
50 rounds, each round sends you a graph (n vertices, edges).
You must return a zero-knowledge proof that the graph is 3-colorable.
You have 5 seconds per round.
nc zkpow.chal.imaginaryctf.org 1337
________________________________________
Step 1 – Understanding the verifier
From the provided server code (zkpow.py):
•	Commit phase: For each vertex v, prover commits to (color, nonce) with
•	leaf = SHA256("vertex:v:color:nonce")
and builds a Merkle tree over all leaves.
•	Challenge: Fiat–Shamir chooses one random edge index as
•	idx = SHA256(merkle_root) mod |edges|
so the verifier’s challenge depends only on the Merkle root.
•	Response: Prover opens the two endpoints of that edge (color + nonce + Merkle proof).
•	Check:
1.	Merkle proofs match the root.
2.	Endpoints are in the opening.
3.	Their colors differ.
That’s it. The verifier never checks all edges, only the single Fiat–Shamir edge.
________________________________________
Step 2 – Where’s the weakness?
•	A valid 3-coloring of the entire graph is unnecessary.
•	You only need the chosen edge’s endpoints to differ.
•	The chosen edge index depends on the Merkle root.
•	So: change your commitments (e.g. tweak nonces) until the root makes Fiat–Shamir pick a “good” edge.
With random colors:
•	Probability endpoints differ = 2/3.
•	So in expectation, 1–2 tries are enough.
________________________________________
Step 3 – Naïve attempt (too slow)
At first, I rebuilt the entire Merkle tree and scanned all edges each retry. This became O(|E|) per round.
By round 20, n ≈ 670, |E| in the hundreds of thousands, and the solver exceeded the 5s limit.
________________________________________
Step 4 – Optimized approach
Two key optimizations:
1.	Don’t scan all edges.
After computing Fiat–Shamir index, just check that one edge’s endpoints differ.
2.	Incremental Merkle updates.
Build the tree once. Then when tweaking a single leaf’s nonce, rehash only its path up to the root (O(log n)) instead of rebuilding the entire tree.
This brought each round back to ~200–2500 ms, safely under the 5s window.
________________________________________
Step 5 – Solver
#!/usr/bin/env python3
from pwn import remote
import os, json, hashlib, random, time

HOST, PORT = "zkpow.chal.imaginaryctf.org", 1337

def H(b): return hashlib.sha256(b).digest()
def leaf_hash(v, c, nonce): return H(b"vertex:%d:%d:" % (v, c) + nonce)

def build_levels(leaves):
    levels = [leaves]; cur = leaves
    while len(cur) > 1:
        nxt = [H(cur[i] + (cur[i+1] if i+1 < len(cur) else cur[i]))
               for i in range(0,len(cur),2)]
        levels.append(nxt); cur = nxt
    return levels

def update_path(levels, idx):
    i = idx
    for d in range(len(levels)-1):
        level, parent = levels[d], levels[d+1]
        sib = i ^ 1; 
        if sib >= len(level): sib = i
        L,R = (level[i],level[sib]) if i%2==0 else (level[sib],level[i])
        parent[i//2] = H(L+R)
        i//=2

def merkle_proof(levels, idx):
    proof=[]; i=idx
    for d in range(len(levels)-1):
        level=levels[d]; sib=i^1
        if sib>=len(level): sib=i
        proof.append((level[sib].hex(), sib%2==0)); i//=2
    return proof

def root_hex(levels): return levels[-1][0].hex()
def fs_idx(root,m): return int.from_bytes(hashlib.sha256(root.encode()).digest(),"big")%m

def solve_round(n, edges):
    colors=[random.randrange(3) for _ in range(n)]
    nonces=[os.urandom(16) for _ in range(n)]
    leaves=[leaf_hash(v,colors[v],nonces[v]) for v in range(n)]
    levels=build_levels(leaves)
    target=0
    while True:
        rhex=root_hex(levels)
        u,v=edges[fs_idx(rhex,len(edges))]
        if colors[u]!=colors[v]:
            openings={}
            for w in (u,v):
                openings[str(w)]={"color":colors[w],"nonce":nonces[w].hex(),
                                  "merkle_proof":merkle_proof(levels,w)}
            return {"merkle_root":rhex,"openings":openings}
        nonces[target]=os.urandom(16)
        levels[0][target]=leaf_hash(target,colors[target],nonces[target])
        update_path(levels,target)

def main():
    io=remote(HOST,PORT)
    io.recvuntil(b"enabled==")
    for i in range(50):
        io.recvuntil(f"==round {i}==".encode())
        buf=io.recvuntil(b"proof:")
        jline=[ln for ln in buf.decode().splitlines() if ln.strip().startswith("{")][-1]
        g=json.loads(jline); n,edges=g["n"],g["edges"]
        proof=solve_round(n,edges)
        io.send((json.dumps(proof,separators=(',',':'))+"\n").encode())
        print(io.recvline().decode().strip())
    print(io.recvall().decode())

if __name__=="__main__": main()
________________________________________
Step 6 – Result
Running the solver:
[round 0] ok in 202.9 ms
...
[round 49] ok in 245.0 ms
flag: ictf{zero_knowledge_proof_more_like_i_have_zero_knowledge_of_how_to_prove_this}
