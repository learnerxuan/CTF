---
ctf: ScarletCTF 2026
category: pwn
difficulty: easy
points: 100
flag: RUSEC{wow_i_did_a_data_race}
techniques:
  - race-condition
  - toctou
  - pipelining
tools:
  - pwntools
  - nc
---

# speedjournal

## Description

Its 2026, I need to start journal-maxing. Thats why I use speedjournal, which lets me brain-max my thoughts while time-maxing with the speed of C! Its also security-maxed so only I can read my private entries!

## Solution

This challenge involves a **race condition vulnerability** (also known as **TOCTOU** - Time of Check, Time of Use).

### Analyzing the Source Code

1. A restricted log entry containing the flag is stored at index 0
2. The `login_admin()` function authenticates with the password "supersecret" and sets `is_admin = 1`
3. However, immediately after setting `is_admin = 1`, it spawns a detached thread that sleeps for 1000 microseconds (1ms) and then sets `is_admin = 0`
4. The `read_log()` function checks if the log is restricted AND if the user is not admin - if both conditions are true, access is denied

### The Vulnerability

There's a **1000 microsecond window** between when `is_admin` is set to 1 and when the logout thread resets it to 0. If we can issue a read request for the restricted log during this window, we can bypass the access control.

### Exploitation Strategy

The key insight is that **network latency is much larger than 1ms**, so we cannot wait for server responses between commands. Instead, we **pipeline all commands** into a single TCP packet:

1. Login command (option 1)
2. Password ("supersecret")
3. Read command (option 3)
4. Index to read (0)

By sending all of these at once, the server processes them in rapid succession. The read request is executed **before the logout thread has a chance to run**.

### Exploit Code

```python
from pwn import *

p = remote('scarletctf.ru.edu', 1337)

# Pipeline all commands in one packet
payload = b"1\n"              # Login
payload += b"supersecret\n"   # Password
payload += b"3\n"             # Read
payload += b"0\n"             # Index 0 (flag)

p.send(payload)
print(p.recvall().decode())
```

## Key Techniques

- **TOCTOU (Time-of-Check-Time-of-Use)** race condition
- Command pipelining to exploit timing windows
- Thread synchronization vulnerability

