Comparing Solution
0) Challenge Files
•	comparing.cpp – hides a flag string, transforms it, and prints numeric lines.
•	output.txt – the numeric lines produced by the program (given to us).
________________________________________
1) What the program does (bird’s-eye view)
1.	Split the hidden flag into pairs:
pair i is (flag[2*i], flag[2*i+1], i).
2.	Push all pairs into a max-heap (priority_queue) ordered by int(c0) + int(c1).
3.	Repeatedly pop two tuples t1=(val1,val2,i1) and t2=(val3,val4,i2), then print two lines:
o	Line for i1 uses (val1, val3)
o	Line for i2 uses (val2, val4)
4.	Whether the line is even or odd depends on the tuple’s index (i1 or i2):
o	even(i) → even(valA,valB,i)
str(valA)+str(valB)+str(i)+reverse(str(valA)+str(valB))
o	odd(i) → odd(valA,valB,i)
str(valA)+str(valB)+str(i) (the “addend” sums to zero)
So each iteration prints two lines that together encode four ASCII codes: (val1,val2) for i1 and (val3,val4) for i2.
________________________________________
2) Decoding rules (what each printed line looks like)
•	Odd line (for odd index i):
ABi
where AB is two ASCII codes concatenated, and the final digits are the index i. There is no mirrored tail.
•	Even line (for even index i):
AB i reverse(AB)
i.e., a mirror/palindrome around the index. If you remove the trailing reverse(AB), the remaining middle ends with i, and the prefix is exactly AB.
Here A and B are decimal ASCII codes of printable characters (32–126). AB typically is 4–6 digits total (because each of A/B is 2–3 digits).
________________________________________
3) How to identify line type + extract (i, A, B)
Goal: from a line, get the tuple (index i, code A, code B).
A. If it’s even:
A valid even line can be recognized by trying all positions of i (0..15 in this challenge) inside the string and checking for the mirrored tail:
•	For each candidate i inside the string:
split line = head + str(i) + tail.
If tail == reverse(head) and head != "", then it’s even with AB = head.
B. If it’s odd:
Check if the line ends with some i (0..15).
If yes, AB = line_without_the_trailing_i.
C. Split AB into two ASCII codes
Try the two plausible splits:
•	A = int(AB[:2]), B = int(AB[2:])
•	A = int(AB[:3]), B = int(AB[3:])
Pick the split where both A and B are in [32..126].
________________________________________
4) Pairing lines to reconstruct characters
The program prints lines in pairs per heap iteration:
•	First line (k) was for index i1, and carries:
o	first char of i1 → val1 = A
o	first char of i2 → val3 = B
•	Second line (k+1) was for index i2, and carries:
o	second char of i1 → val2 = C
o	second char of i2 → val4 = D
Therefore, from lines (k, k+1):
•	pair[i1] = (val1, val2) = (A, C)
•	pair[i2] = (val3, val4) = (B, D)
Repeat for (0,1), (2,3), ….
Finally, order pair[0], pair[1], … pair[N-1] and convert ASCII codes to characters to get the flag.
________________________________________
5) Manual example with the first two lines
Given the first two lines of output.txt:
0: 9548128459
1: 491095
Line 0 → detect even
Try i=12:
"9548" + "12" + "8459" and "8459" == reverse("9548") ✅
So it’s even, i=12, and AB="9548".
Split AB:
•	95 and 48 → ASCII: 95 '_', 48 '0'
So line 0 gives:
•	for i1=12: first char '_' (95)
•	for the other index i2: first char '0' (48)
Line 1 → detect odd
The line ends with "5" → i=5, AB="49109".
Split AB:
•	49 and 109 → ASCII: 49 '1', 109 'm'
So line 1 gives:
•	for i1=12: second char '1' (49)
•	for i2=5: second char 'm' (109)
Put together:
•	pair[12] = ('_', '1')
•	pair[5] = ('0', 'm')
Do this for each subsequent line pair.
________________________________________
6) Full decoder (Python)
Save as decoder.py next to output.txt.
# decoder.py
def detect_even_all_positions(s, max_i=32):
    hits = []
    for i in range(max_i):
        t = str(i)
        start = 0
        while True:
            pos = s.find(t, start)
            if pos == -1:
                break
            head = s[:pos]
            tail = s[pos+len(t):]
            if head and tail == head[::-1]:
                hits.append((i, head))
            start = pos + 1
    return hits

def split_two_ascii(ab):
    """Try 2/3-digit splits for A, rest for B; keep printable ASCII [32..126]."""
    pairs = []
    for l1 in (2, 3):
        if l1 < len(ab):
            a, b = int(ab[:l1]), int(ab[l1:])
            if 32 <= a <= 126 and 32 <= b <= 126:
                pairs.append((a, b))
    return pairs

def decode_options(line, max_i=32):
    s = line.strip()
    opts = []

    # Try even pattern (mirror around i anywhere in the string)
    for idx, ab in detect_even_all_positions(s, max_i):
        for a, b in split_two_ascii(ab):
            opts.append(("even", idx, (a, b)))

    # Try odd pattern (endswith i)
    for idx in range(max_i):
        t = str(idx)
        if s.endswith(t) and len(s) > len(t):
            ab = s[:-len(t)]
            for a, b in split_two_ascii(ab):
                opts.append(("odd", idx, (a, b)))

    return opts

def main():
    lines = [l.strip() for l in open("output.txt").read().splitlines() if l.strip()]
    opts_per_line = [decode_options(l, max_i=64) for l in lines]

    # In this challenge, each line has a unique valid decode, so pick [0]
    pairs = {}
    for k in range(0, len(lines), 2):
        kind0, i1, (a, b) = opts_per_line[k][0]     # i1 line uses (val1, val3)
        kind1, i2, (c, d) = opts_per_line[k+1][0]   # i2 line uses (val2, val4)

        pairs[i1] = (a, c)  # i1 -> (first, second)
        pairs[i2] = (b, d)  # i2 -> (first, second)

    # Stitch by index order
    flag_bytes = []
    for i in range(len(pairs)):
        first, second = pairs[i]
        flag_bytes.extend([first, second])

    flag = bytes(flag_bytes).decode()
    print(flag)

if __name__ == "__main__":
    main()
Run
python3 decoder.py
Output
ictf{cu3st0m_c0mp@r@t0rs_1e8f9e}
