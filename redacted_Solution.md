redacted Solution
________________________________________
Challenge
wait, i thought XORing something with itself gives all 0s???
We are given a ciphertext:
65 6c ce 6b c1 75 61 7e 53 66 c9 52 d8 6c 6a 53
6e 6e de 52 df 63 6d 7e 75 7f ce 64 d5 63 73
________________________________________
Step 1: Analyzing the hint
The challenge hint reminds us of the XOR properties:
•	x ⊕ x = 0
•	x ⊕ 0 = x
This suggests the scheme is XOR-based encryption, possibly with the flag itself (or part of it) used as the key.
________________________________________
Step 2: Known plaintext
In ImaginaryCTF, flags always start with ictf{ and end with }.
That means we already know part of the plaintext. If we XOR ciphertext with plaintext, we can directly recover the key bytes:
key[i] = cipher[i] ⊕ plain[i]
This gives us the repeating key used in the XOR scheme.
________________________________________
Step 3: Solving with Python
We wrote a solver that:
1.	Guesses possible key lengths.
2.	Uses the known prefix ictf{ and suffix } to recover key bytes.
3.	Checks that the decrypted plaintext is printable and flag-shaped.
cipher_hex = """
65 6c ce 6b c1 75 61 7e 53 66 c9 52 d8 6c 6a 53
6e 6e de 52 df 63 6d 7e 75 7f ce 64 d5 63 73
""".strip().replace("\n"," ")

C = bytes.fromhex(cipher_hex)

def solve():
    for L in range(2, 32):
        key = [None]*L
        known = [(0, ord('i')), (1, ord('c')), (2, ord('t')), (3, ord('f')), (4, ord('{')),
                 (len(C)-1, ord('}'))]
        ok = True
        for i, ch in known:
            k = C[i] ^ ch
            r = i % L
            if key[r] is None:
                key[r] = k
            elif key[r] != k:
                ok = False
                break
        if not ok: continue

        P = bytes(C[i] ^ key[i % L] for i in range(len(C)))
        if P.startswith(b"ictf{") and P.endswith(b"}"):
            return P.decode()

print(solve())
________________________________________
Step 4: Result
Running the solver recovers:
ictf{xor_is_bad_bad_encryption}
