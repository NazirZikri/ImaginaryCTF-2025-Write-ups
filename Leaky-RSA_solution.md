Leaky-RSA Solution
Challenge Description
We connect to:
nc leaky-rsa.chal.imaginaryctf.org 1337
The server gives us:
•	an RSA modulus n
•	an RSA ciphertext c = key_m^e mod n
•	an AES-CBC IV and ciphertext of the flag
Then it runs 1024 “oracle rounds.” In each round it:
•	chooses a random index idx ∈ {0,1,2,3}
•	asks us to submit a JSON object {"c": some_ciphertext}
•	decrypts it to m = c^d mod n
•	replies with {"b": m[idx]} (the bit at position idx in m)
•	if our input is invalid, it returns b = 2
At the end, the provided source code even prints out the secret key_m.
The AES key is derived from the secret:
key = sha256(str(key_m).encode()).digest()[:16]
The flag is AES-CBC encrypted with this key.
________________________________________
Vulnerability
The intended design: we can only see 4 low bits per query. But because RSA is multiplicatively homomorphic,
(m1e)(m2e)≡(m1m2)e(modn),(m_1^e)(m_2^e) \equiv (m_1 m_2)^e \pmod{n},(m1e)(m2e)≡(m1m2)e(modn), 
we can multiply the original ciphertext by 2te2^{te}2te to shift the bits of key_m into the lowest 4 positions, then query the oracle and reconstruct key_m bit by bit.
So in principle, 1024 oracle rounds are enough to recover ~1024 bits of key_m.
________________________________________
Easy Mode (what was actually deployed)
In the given chall.py the authors accidentally left a debug line:
print(key_m)
So the service still prints the secret at the end!
That means we don’t even need to perform the bit-oracle attack. We just have to:
1.	Reply with any valid ciphertext each round (to avoid b=2 errors).
2.	Read key_m at the end.
3.	Derive the AES key.
4.	Decrypt the flag.
________________________________________
Exploit Code
from pwn import remote
import json
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST, PORT = "leaky-rsa.chal.imaginaryctf.org", 1337
E = 65537

def recv_json(io):
    while True:
        line = io.recvline().decode().strip()
        if line.startswith("{"):
            return json.loads(line)

io = remote(HOST, PORT)

# 1) Initial banner
head = recv_json(io)
n = int(head["n"])
key_c = int(head["c"])
iv = bytes.fromhex(head["iv"])
ct = bytes.fromhex(head["ct"])

# 2) Pick a safe ciphertext != key_c
fixed_c = pow(2, E, n)
if fixed_c == key_c:
    fixed_c = pow(3, E, n)

# 3) Answer 1024 rounds
for _ in range(1024):
    _ = recv_json(io)                              # {"idx": k}
    io.sendline(json.dumps({"c": fixed_c}).encode())
    _ = recv_json(io)                              # {"b": ...}

# 4) Get key_m from the final line
key_m = int(io.recvline().decode().strip())

# 5) Derive AES key and decrypt
key = sha256(str(key_m).encode()).digest()[:16]
pt = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
print(pt.decode())
________________________________________
Result
Running the solver yields the decrypted flag:
ictf{p13cin9_7h3_b1t5_t0g37her_3f0068c1b9be2547ada52a8020420fb0}
