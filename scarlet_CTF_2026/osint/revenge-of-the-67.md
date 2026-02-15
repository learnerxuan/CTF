---
ctf: ScarletCTF 2026
category: osint
difficulty: easy
points: 100
flag: RUSEC{HELP-THEY-PUT-ME-IN-A-DNS-RECORD}
techniques:
  - dns-enumeration
  - star-wars-reference
  - txt-record-lookup
tools:
  - dig
  - nslookup
---

# Revenge of the 67

## Description

An OSINT challenge where a prisoner describes being shot and captured. They mention that a "leader" tried to make a web exploitation challenge for the CTF but didn't finish, so the infrastructure was taken down. However, some DNS records might still exist. The challenge hints to look for the leader's name in lowercase with honoraries removed (e.g., "King Ben Swolo" → "ben_swolo").

## Solution

### 1. Identify the CTF domain

The challenge is from Scarlet CTF, hosted by RUSEC (Rutgers Security Club) at `ctf.rusec.club`.

### 2. Decode the "67" reference

"Revenge of the 67" is a play on "Revenge of the Sith" (Star Wars Episode III). In Star Wars, Order 66 was the command to kill the Jedi. Order 67 is a joke reference from LEGO Star Wars. This hints at **Star Wars characters**.

### 3. Identify the "leader"

The challenge mentions looking for a name with "honoraries removed." In Star Wars, **"General Grievous"** is a military leader. Removing the honorary title "General" gives us **"grievous"**.

### 4. Query DNS TXT records

Check for TXT records at `grievous.ctf.rusec.club`:

```bash
dig TXT grievous.ctf.rusec.club
```

Output:
```
grievous.ctf.rusec.club. 300 IN TXT "RUSEC{HELP-THEY-PUT-ME-IN-A-DNS-RECORD}"
```

## Key Techniques

- Pop culture reference decoding (Star Wars)
- DNS TXT record enumeration
- Subdomain discovery through contextual hints

