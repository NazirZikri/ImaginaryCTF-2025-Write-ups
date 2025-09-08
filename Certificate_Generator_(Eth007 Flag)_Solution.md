Certificate Generator (Eth007 Flag) Solution
Challenge Description
As a thank you for playing our CTF, we’re giving out participation certificates! Each one comes with a custom flag, but I bet you can’t get the flag belonging to Eth007!
Target URL:
https://eth007.me/cert/
________________________________________
Recon
Visiting the page shows a certificate generator form with fields like Name, Title, Date, and a preview/download option. The certificate itself is rendered as an SVG in the browser.
Inspecting the page source (Ctrl+U) or using DevTools revealed a long JavaScript section responsible for rendering the certificate.
________________________________________
Source Analysis
Key functions inside the script:
function customHash(str){
  let h = 1337;
  for (let i=0;i<str.length;i++){
    h = (h * 31 + str.charCodeAt(i)) ^ (h >>> 7);
    h = h >>> 0; // force unsigned
  }
  return h.toString(16);
}

function makeFlag(name){
  const clean = name.trim() || "anon";
  const h = customHash(clean);
  return `ictf{${h}}`;
}
The SVG certificate includes:
<desc>ictf{<hash>}</desc>
So the flag = ictf{customHash(participantName)}.
________________________________________
The Twist
Inside the rendering function:
if (name == "Eth007") {
  name = "REDACTED";
}
The site blocks users from directly generating Eth007’s certificate — it swaps "Eth007" to "REDACTED".
________________________________________
Exploitation
Since the flag is purely computed in JavaScript, we can bypass the UI by simply running the hash function ourselves.
In DevTools Console:
customHash("Eth007").toString(16);
// -> "7b4b3965"
Then:
makeFlag("Eth007");
// -> "ictf{7b4b3965}"
________________________________________
Flag
ictf{7b4b3965}
