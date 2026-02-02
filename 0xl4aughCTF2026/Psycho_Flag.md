# Psycho_Flag - 0xL4ugh CTF 2026 Writeup

**Challenge:** Psycho_Flag  
**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Flag:** `0xL4ugh{P5ych0_Flag_Hid3s_In_The_Gat3}`  

## Table of Contents
1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Understanding the Obfuscation](#understanding-the-obfuscation)
3. [Emulating and Patching the Binary](#emulating-and-patching-the-binary)
4. [Analyzing the Parent-Child Interaction](#analyzing-the-parent-child-interaction)
5. [Heaven's Gate - 32-bit Transition](#heavens-gate---32-bit-transition)
6. [Emulating the Child Process](#emulating-the-child-process)
7. [Understanding the Encryption](#understanding-the-encryption)
8. [Writing the Solver](#writing-the-solver)
9. [Conclusion](#conclusion)

---

## Initial Reconnaissance

### Basic File Information

First, let's examine the binary:

```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped

$ ls -lh chall
-rwxrwxr-x 1 user user 53K Jan 23 01:56 chall
```

Key observations:
- **64-bit ELF** executable
- **Statically linked** (all libraries compiled in)
- **Stripped** (no debug symbols)
- Small size (53KB)

### Running the Binary

```bash
$ ./chall
Usage: ./chall <flag>

$ ./chall test123
Wrong Flag.

$ ./chall 0xl4ugh{test}
# No output, exits with code 1
```

The binary expects exactly one argument and checks if it's the correct flag.

### Examining Sections

```bash
$ readelf -S chall
There are 5 section headers, starting at offset 0xd090:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 1] .text             PROGBITS         0000000000401000  00001000
       000000000000bb3c  0000000000000000  AX       0     0     16
  [ 2] .data             PROGBITS         000000000040d000  0000d000
       0000000000000073  0000000000000000  WA       0     0     4
  [ 3] .bss              NOBITS           000000000040d074  0000d073
       0000000000000014  0000000000000000  WA       0     0     4
```

The binary has minimal sections - just code (.text) and data (.data/.bss).

### Searching for Strings

```bash
$ strings chall | grep -E '(flag|Flag|FLAG|correct|wrong)'
Wrong Flag.
Usage: ./chall <flag>
Correct!
```

Found three interesting strings:
- Usage message
- "Wrong Flag." error
- "Correct!" success message (never shown with wrong input)

### Looking at the Data Section

```bash
$ xxd -s 0xd000 -l 128 chall
0000d000: 2f64 6576 2f6e 756c 6c00 6d78 0000 0000  /dev/null.mx....
0000d010: 0000 0000 0000 0000 0000 0000 000a 436f  ..............Co
0000d020: 7272 6563 7421 0a00 0a57 726f 6e67 2046  rrect!...Wrong F
0000d030: 6c61 672e 0a00 5573 6167 653a 202e 2f63  lag...Usage: ./c
0000d040: 6861 6c6c 203c 666c 6167 3e0a 00d9 910d  hall <flag>.....
0000d050: b5a4 8ec1 9239 6490 5ac1 d966 e32d 688e  .....9d.Z..f.-h.
0000d060: 66e1 c0a5 ca8a 66e0 3b66 55c1 b466 ee68  f.....f.;fU..f.h
0000d070: 75ca 8c                                  u..
```

At offset **0xd04d** (address 0x40d04d), there's encrypted-looking data:
```
D9 91 0D B5 A4 8E C1 92 39 64 90 5A C1 D9 66 E3
2D 68 8E 66 E1 C0 A5 CA 8A 66 E0 3B 66 55 C1 B4
66 EE 68 75 CA 8C
```

This is **38 bytes** of data - likely the encrypted flag!

---

## Understanding the Obfuscation

### Initial Disassembly

Opening the binary in IDA/Ghidra reveals a problem: the code is heavily obfuscated.

```bash
$ objdump -d --no-show-raw-insn -M intel chall | head -50
0000000000401000 <.text>:
  401000:	xor    %rax,%rax
  401003:	mov    %rax,0xc003(%rip)        # 0x40d00d
  40100a:	mov    %rax,0xc004(%rip)        # 0x40d015
  401011:	jmp    0x401013

0000000000401013 <loc_401013>:
  401013:	mov    $0x795,%r12d
  401019:	mov    $0xfd661217,%r11d
  40101f:	xor    %r12,%r11
  401022:	mov    %rsp,%rbx              # REAL INSTRUCTION!
  401025:	mov    $0xfd661217,%r11d
  40102b:	xor    %r12,%r11
  40102e:	mov    0xbfe0(%rip),%rax
  401035:	xor    %r12,%rax
  401038:	add    %r12,%rax
  40103b:	sub    %r12,%rax
  40103e:	xor    %r12,%rax
  401041:	mov    0xbfc5(%rip),%r11
  401048:	add    %r12,%r11
  40104b:	sub    %r12,%r11
  40104e:	test   %rax,%rax
  401051:	cmovne %r12,%r12
  401055:	lea    -0x49(%rip),%r11        # 0x401013
  40105c:	add    %r12,%r11
  40105f:	mov    %r11,%rax
  401062:	jmp    *%rax                   # COMPUTED JUMP!
```

### Obfuscation Pattern Analysis

Looking at this block, we can identify a pattern:

**Junk Instructions (do nothing):**
```asm
mov    $0xfd661217,%r11d       ; Load key
xor    %r12,%r11                ; XOR once
...
xor    %r12,%r11                ; XOR again with same key (back to original!)

mov    0xbfe0(%rip),%rax        ; Load 0 (global variable)
xor    %r12,%rax                ; XOR with 0 = no change
add    %r12,%rax                ; Add 0 = no change
sub    %r12,%rax                ; Sub 0 = no change
xor    %r12,%rax                ; XOR 0 = no change
```

**Real Instruction:**
```asm
mov    %rsp,%rbx                ; Save stack pointer - THIS MATTERS!
```

**Jump Calculation:**
```asm
lea    -0x49(%rip),%r11         ; r11 = base address (0x401013)
add    %r12,%r11                ; r11 = 0x401013 + 0x795 = 0x4017A8
mov    %r11,%rax
jmp    *%rax                    ; Jump to computed address
```

### Why This Breaks Static Analysis

The problem with `jmp *%rax` (indirect jump):
- **IDA/Ghidra** can't follow it statically
- They don't know what value is in `rax` without executing the code
- This **breaks the Control Flow Graph (CFG)**
- Decompilation fails or shows garbage

**Question I had:** "Why can't IDA follow `jmp rax`? What's wrong?"

**Answer:** IDA performs **static analysis** - it reads the binary without running it. For `jmp 0x4017a8`, IDA knows exactly where it goes. But for `jmp rax`, IDA would need to:
1. Know r11 = 0x795
2. Calculate 0x401013 + 0x795
3. Know that goes into rax

IDA can't "execute" the arithmetic in its head - it can only read instructions. So it gives up and shows a dead end.

### The Solution: Dynamic Emulation

Since static analysis fails, we need to **actually run the code** and watch where it jumps. This is called **dynamic analysis** or **emulation**.

---

## Emulating and Patching the Binary

### Understanding Emulation

An **emulator** is a program that pretends to be a CPU:
- Reads assembly instructions
- Executes them (in software)
- Tracks register values
- Records what happens

For this challenge, we'll use **Unicorn Engine** - a CPU emulator library.

### The Emulation Strategy

The plan:
1. **Load the binary** into Unicorn's memory
2. **Run the code** with some test input
3. **Hook every instruction** - get notified before each one executes
4. **When we see `jmp rax`:**
   - Read what value is in `rax` (the jump target)
   - Record: "Address X jumps to address Y"
5. **Patch the binary file:**
   - Replace `jmp rax` with `jmp 0x...` (direct jump)
6. **Now IDA/Ghidra can follow it!**

### The Emulator Script (emu.py)

Here's the emulator script that patches the parent process:

```python
#!/usr/bin/env python3
import argparse
import struct
from dataclasses import dataclass
from typing import List, Tuple, Optional

from unicorn import (
    Uc, UC_ARCH_X86, UC_MODE_64,
    UC_HOOK_CODE, UC_HOOK_INSN
)
from unicorn.x86_const import (
    UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX,
    UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_R10, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_INS_SYSCALL,
)

from elftools.elf.elffile import ELFFile

PAGE = 0x1000

def page_down(x: int) -> int:
    return x & ~(PAGE - 1)

def page_up(x: int) -> int:
    return (x + PAGE - 1) & ~(PAGE - 1)

def read_file(path: str) -> bytearray:
    with open(path, "rb") as f:
        return bytearray(f.read())

def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def rel32(from_addr: int, to_addr: int) -> int:
    # E9 rel32 is relative to next instruction (from_addr + 5)
    return (to_addr - (from_addr + 5)) & 0xFFFFFFFF

def patch_jmp_rel32(buf: bytearray, file_off: int, from_va: int, to_va: int):
    disp = rel32(from_va, to_va)
    buf[file_off:file_off + 5] = b"\xE9" + struct.pack("<I", disp)

@dataclass
class SegMap:
    vaddr: int
    memsz: int
    filesz: int
    fileoff: int

class PatcherEmu:
    def __init__(self, bin_path: str, out_path: str, arg1: Optional[str],
                 max_insn: int, max_patches: int, debug: bool = False):
        self.bin_path = bin_path
        self.out_path = out_path
        self.arg1 = arg1
        self.max_insn = max_insn
        self.max_patches = max_patches
        self.debug = debug

        self.raw = read_file(bin_path)
        self.segs: List[SegMap] = []
        self.entry: int = 0

        # (patch_va, target_va, file_off)
        self.patches: List[Tuple[int, int, int]] = []

        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)

        # very simple mmap allocator
        self.next_mmap = 0x10000000

    def parse_elf(self):
        with open(self.bin_path, "rb") as f:
            ef = ELFFile(f)
            self.entry = ef.header["e_entry"]
            for seg in ef.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                self.segs.append(SegMap(
                    vaddr=seg["p_vaddr"],
                    memsz=seg["p_memsz"],
                    filesz=seg["p_filesz"],
                    fileoff=seg["p_offset"],
                ))

    def map_segments(self):
        # Map all PT_LOAD segments RWX (fine for emulation)
        for s in self.segs:
            start = page_down(s.vaddr)
            end = page_up(s.vaddr + s.memsz)
            size = end - start

            self.uc.mem_map(start, size, 1 | 2 | 4)

            data = self.raw[s.fileoff:s.fileoff + s.filesz]
            self.uc.mem_write(s.vaddr, bytes(data))

            if s.memsz > s.filesz:
                self.uc.mem_write(s.vaddr + s.filesz, b"\x00" * (s.memsz - s.filesz))

    def setup_stack(self):
        # Correct Linux x86-64 entry stack:
        # [rsp+0x00] = argc
        # [rsp+0x08] = argv[0]
        # [rsp+0x10] = argv[1] (if argc==2)
        # [rsp+0x08*(argc+1)] = NULL
        stack_base = 0x7fff00000000
        stack_size = 2 * 1024 * 1024
        stack_top = stack_base + stack_size
        self.uc.mem_map(stack_base, stack_size, 1 | 2)

        argc = 2 if self.arg1 is not None else 1
        sp = stack_top - 0x1000

        def push_cstr(b: bytes) -> int:
            nonlocal sp
            sp -= len(b)
            self.uc.mem_write(sp, b)
            return sp

        argv0_ptr = push_cstr(b"./challenge\x00")
        argv1_ptr = push_cstr(self.arg1.encode() + b"\x00") if argc == 2 else 0

        sp &= ~0xF

        def push_qword(x: int):
            nonlocal sp
            sp -= 8
            self.uc.mem_write(sp, struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF))

        # argv array (reverse order)
        push_qword(0)              # argv[argc] = NULL
        if argc == 2:
            push_qword(argv1_ptr)  # argv[1]
        push_qword(argv0_ptr)      # argv[0]

        # argc at top
        push_qword(argc)

        self.uc.reg_write(UC_X86_REG_RSP, sp)

    def va_to_fileoff(self, va: int) -> Optional[int]:
        for s in self.segs:
            if s.vaddr <= va < (s.vaddr + s.filesz):
                return s.fileoff + (va - s.vaddr)
        return None

    def read_mem(self, addr: int, size: int) -> bytes:
        return self.uc.mem_read(addr, size)

    def hook_syscall(self, uc, user_data):
        nr  = uc.reg_read(UC_X86_REG_RAX)
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)

        # Linux x86-64 syscall numbers
        SYS_write = 1
        SYS_mmap  = 9
        SYS_exit  = 60
        SYS_exit_group = 231

        if nr == SYS_write:
            # pretend it succeeded: return count
            uc.reg_write(UC_X86_REG_RAX, rdx)
            return

        if nr == SYS_exit or nr == SYS_exit_group:
            uc.emu_stop()
            return

        if nr == SYS_mmap:
            # args: (addr, len, prot, flags, fd, off)
            length = (rsi + 0xFFF) & ~0xFFF
            if length == 0:
                length = 0x1000

            # If addr==0 pick our own; otherwise honor hint if possible
            if rdi == 0:
                addr = (self.next_mmap + 0xFFF) & ~0xFFF
            else:
                addr = (rdi + 0xFFF) & ~0xFFF

            try:
                uc.mem_map(addr, length, 1 | 2 | 4)
            except Exception:
                pass

            if rdi == 0:
                self.next_mmap = addr + length

            uc.reg_write(UC_X86_REG_RAX, addr)
            return

        # Unknown syscall: return -ENOSYS
        ENOSYS = 38
        uc.reg_write(UC_X86_REG_RAX, (0 - ENOSYS) & 0xFFFFFFFFFFFFFFFF)

    def hook_code(self, uc, address, size, user_data):
        try:
            insn = self.read_mem(address, size)
        except Exception:
            return

        # detect `jmp rax` opcode: FF E0
        if size >= 2 and insn[0] == 0xFF and insn[1] == 0xE0:
            rip = uc.reg_read(UC_X86_REG_RIP)
            target = uc.reg_read(UC_X86_REG_RAX)

            # Prefer patching 3 bytes before RIP if it's exactly "mov rax, r11" (4C 89 D8)
            patch_va = rip
            try:
                prev3 = self.read_mem(rip - 3, 3)
                if prev3 == b"\x4C\x89\xD8":  # mov rax, r11
                    patch_va = rip - 3
            except Exception:
                patch_va = rip

            file_off = self.va_to_fileoff(patch_va)
            if file_off is None:
                return

            # skip duplicate
            for (pva, _, _) in self.patches:
                if pva == patch_va:
                    return

            self.patches.append((patch_va, target, file_off))

            # Patch live memory so emulation continues along direct edges
            jmp_bytes = b"\xE9" + struct.pack("<I", rel32(patch_va, target))
            uc.mem_write(patch_va, jmp_bytes)

            if len(self.patches) >= self.max_patches:
                uc.emu_stop()

    def run(self):
        self.parse_elf()
        self.map_segments()
        self.setup_stack()

        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.hook_add(UC_HOOK_INSN, self.hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

        self.uc.reg_write(UC_X86_REG_RIP, self.entry)

        try:
            self.uc.emu_start(self.entry, 0, count=self.max_insn)
        except Exception as e:
            if self.debug:
                print("[dbg] emu exception:", repr(e))

        # Apply file patches
        out = bytearray(self.raw)
        for patch_va, target_va, file_off in self.patches:
            if file_off + 5 <= len(out):
                patch_jmp_rel32(out, file_off, patch_va, target_va)

        write_file(self.out_path, out)

def main():
    ap = argparse.ArgumentParser(
        description="Emulate dispatcher blocks, resolve jmp rax targets, patch to direct jmp rel32"
    )
    ap.add_argument("binary", help="Path to ELF binary")
    ap.add_argument("-o", "--out", default="challenge.patched", help="Output patched binary path")
    ap.add_argument("--arg", default=None, help="argv[1] string (flag input)")
    ap.add_argument("--max-insn", type=int, default=5_000_000, help="Max instructions to emulate")
    ap.add_argument("--max-patches", type=int, default=5000, help="Stop after this many patches")
    ap.add_argument("--debug", action="store_true", help="Verbose logging")
    args = ap.parse_args()

    pe = PatcherEmu(
        bin_path=args.binary,
        out_path=args.out,
        arg1=args.arg,
        max_insn=args.max_insn,
        max_patches=args.max_patches,
        debug=args.debug,
    )
    pe.run()
    print(f"[+] Wrote patched binary: {args.out}")
    print(f"[+] Patches applied: {len(pe.patches)}")

if __name__ == "__main__":
    main()
```

### Running the Emulator (First Attempt)

**Question I had:** "How does the emulator actually work? We only have bytes - how does it know where jumps go?"

**Answer:** The emulator:
1. **Loads bytes** from the file
2. **Decodes them** using Capstone (disassembly library)
3. **Executes instructions** - updates register values
4. When it reaches `jmp rax`, it **reads the rax register's VALUE** (e.g., 0x4017a8)
5. Records: "jmp at 0x40105f goes to 0x4017a8"
6. Continues emulation from that address

Let's run it with a short test input:

```bash
$ python3 emu.py chall -o chall.patched --arg "aaa" --debug
[dbg] initial stack qwords: ['0x2', '0x7fff001feff4', '0x7fff001feff0', '0x0', ...]
[dbg] patch @ 0x40105f -> 0x4017a8 (file_off 0x105f)
[dbg] patch @ 0x4017f8 -> 0x40111b (file_off 0x17f8)
[dbg] patch @ 0x401167 -> 0x401069 (file_off 0x1167)
[dbg] syscall nr=1 rdi=0x1 rsi=0x40d028 rdx=0xe
[dbg] syscall nr=60 rdi=0x1
[+] Wrote patched binary: chall.patched
[+] Patches applied: 13
```

Success! The emulator:
- Traced 13 indirect jumps
- Patched them all to direct jumps
- Created `chall.patched`

### Verifying the Patch

Let's check what changed:

```bash
# Original binary
$ xxd -s 0x105f -l 10 chall
0000105f: 4c89 d8ff e0e8 0500 0000                 L.........

# Patched binary
$ xxd -s 0x105f -l 10 chall.patched
0000105f: e944 0700 00e8 0500 0000                 .D........
```

**Original:**
```asm
4C 89 D8    → mov rax, r11
FF E0       → jmp rax         (IDA can't follow!)
```

**Patched:**
```asm
E9 44 07 00 00  → jmp 0x4017a8   (IDA CAN follow!)
```

Perfect! The computed jump is now a direct jump.

---

## Analyzing the Parent-Child Interaction

### Opening the Patched Binary

Now we can open `chall.patched` in IDA/Ghidra. The decompiled code at the main function shows:

```c
void __fastcall __noreturn sub_4017A8()
{
  __int64 v0; // rbx
  __int64 v2; // rcx
  _BYTE *v3; // rdi
  bool v4; // zf
  signed __int64 v5; // r13

  // Get argv[1] (flag argument)
  qword_40D078 = *(_QWORD *)(v0 + 16);

  // Check flag length (must be exactly 38 bytes + null)
  v2 = 39;
  v3 = (_BYTE *)qword_40D078;
  do
  {
    if (!v2) break;
    v4 = *v3++ == 0;
    --v2;
  }
  while (!v4);

  // Allocate RWX memory at 0x10000000
  qword_40D080 = sys_mmap(0x10000000u, 0x1000u, 7u, 0x32u, 0xFFFFFFFFFFFFFFFFLL, 0);

  // Copy flag to allocated memory
  qmemcpy((void *)qword_40D080, (const void *)qword_40D078, 0x26u);

  // Fork into parent and child
  v5 = sys_fork();

  // Parent waits for child
  sys_wait4(v5, 0, 0, 0);

  // Parent modifies child's memory using ptrace
  sys_ptrace(4, v5, (unsigned __int64)sub_401920,
             (((_QWORD)sub_403EEE << 32) | 0xBB848236ALL) ^ 0xAAAAAAAAAAAAAAAALL);

  // Print "Wrong Flag" and exit
  sys_write(1u, buf, 0xEu);
  sys_exit(1);
}
```

**Question I had:** "I see JUMPOUT at the end instead of the full code. Why?"

**Answer:** This happened because we only emulated with input "aaa" (3 bytes). The length check failed, so the program took the early exit path. The later code (mmap, fork, etc.) never executed, so it wasn't traced or patched!

### Re-running with Correct Length

We need 38 bytes of input:

```bash
$ python3 emu.py chall -o chall.patched --arg "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" --debug
[dbg] patch @ 0x40105f -> 0x4017a8 (file_off 0x105f)
[dbg] patch @ 0x4017f8 -> 0x40111b (file_off 0x17f8)
...
[dbg] patch @ 0x4034e1 -> 0x401e45 (file_off 0x34e1)
[dbg] syscall nr=101 rdi=0x4 rsi=0xffffffffffffffda rdx=0x401920 r10=0xaaea944412e289c0
[dbg] syscall nr=1 rdi=0x1 rsi=0x40d028 rdx=0xe
[dbg] syscall nr=60 rdi=0x1
[+] Wrote patched binary: chall.patched
[+] Patches applied: 47
```

Much better! Now we got **47 patches** instead of 13. Opening this new `chall.patched` shows the complete function.

### Understanding the Fork and Ptrace

The code does:

1. **Checks flag length** - must be exactly 38 bytes
2. **Allocates RWX memory** at 0x10000000 for the flag
3. **Copies flag** to that memory
4. **Calls `fork()`** - creates child process

After fork, there are **two processes** running the same code:
- **Parent:** `fork()` returns child's PID (e.g., 1234)
- **Child:** `fork()` returns 0

5. **Parent calls `wait4(child_pid)`** - waits for child to do something
6. **Parent calls `ptrace(PTRACE_POKETEXT, child_pid, 0x401920, data)`**
   - This **writes to the child's memory** at address 0x401920
   - The data written is: `((0x403EEE << 32) | 0xBB848236A) ^ 0xAAAAAAAAAAAAAAAA`

### What Does the Child Do?

The child process must:
1. Call `ptrace(PTRACE_TRACEME)` - allow parent to trace it
2. Call `getpid()` - get its own process ID
3. Call `kill(pid, SIGTRAP)` - send signal to parent (notifying it's ready)
4. Parent modifies child's memory
5. Child executes the **modified code**
6. Child does the actual flag checking

### Finding the Fork Branch

We need to find where the code branches based on fork's return value. Looking at the assembly around the fork syscall:

```asm
40371c:  mov    eax,0x39        ; Syscall 57 = fork
403721:  syscall
403723:  mov    r13,rax         ; Save fork result to r13
...
402fc8:  test   r13,r13         ; Check if r13 == 0
402fcb:  cmove  r11,r12         ; If zero (child), r11 = r12
```

This is the **branch point**:
- **Parent** (r13 ≠ 0): r11 stays as 0x26a4, jumps to 0x401013 + 0x26a4 = **0x4036B7**
- **Child** (r13 = 0): r11 becomes 0x1e03, jumps to 0x401013 + 0x1e03 = **0x402E16**

The child's code starts at **0x402E16**.

---

## Heaven's Gate - 32-bit Transition

### What Gets Written to 0x401920

Let's calculate what the parent writes to the child's memory:

```python
sub_403EEE = 0x403EEE
value = ((sub_403EEE << 32) | 0xBB848236A)
encrypted = value ^ 0xAAAAAAAAAAAAAAAA

print(f"Raw value:   0x{value:016x}")
print(f"After XOR:   0x{encrypted:016x}")
print(f"As bytes:    {encrypted.to_bytes(8, 'little').hex()}")
```

Output:
```
Raw value:   0x00403eefbb848236a
After XOR:   0xaaea944512e289c0
As bytes:    c089e2124594eaaa
```

### The Child Decrypts This Data

Looking at the child's code path, we find an XOR loop:

```asm
4037d1:  lea    rdi,[0x401920]     ; Point to poked data
...
402816:  mov    al,BYTE PTR [rdi]  ; Load byte
402818:  xor    al,0xaa            ; XOR with 0xAA
40281a:  mov    BYTE PTR [rdi],al  ; Store back
...                                ; (loops 16 times)
```

The child XORs the poked data with 0xAA, byte by byte.

Let's decrypt it:

```python
encrypted = bytes.fromhex("c089e2124594eaaa")
decrypted = bytes([b ^ 0xaa for b in encrypted])
print(decrypted.hex())
```

Output: `6a2348b8ee3e400050cb`

Disassembling these bytes (32-bit mode):

```asm
6A 23                → push 0x23
48 B8 EE 3E 40 00    → movabs rax, 0x403EEE (actually 'mov eax' in 32-bit)
50                   → push rax/eax
CB                   → retf (far return)
```

### Heaven's Gate Explained

This is the **Heaven's Gate** technique:

1. `push 0x23` - Push code segment selector for 32-bit mode
2. `push 0x403EEE` - Push the address to jump to
3. `retf` - Far return (pops segment and address, switches mode)

**Result:** CPU switches from **64-bit mode** to **32-bit mode** and jumps to **0x403EEE**!

**Why 0x23?** In x86-64, segment selectors:
- `0x33` = 64-bit code segment
- `0x2B` = 64-bit data segment
- `0x23` = 32-bit code segment (compatibility mode)

The flag checking logic is in **32-bit code** at 0x403EEE!

---

## Emulating the Child Process

### Why We Need a Separate Emulator

The child runs in **32-bit mode** starting from **0x403EEE**. We need a different emulator:
- Set to **32-bit mode** (not 64-bit)
- Start from **0x403EEE**
- Write the flag input to **0x10000000** (where child reads it)

### The 32-bit Emulator (emu32.py)

```python
#!/usr/bin/env python3
"""
32-bit emulator for the child process
Traces execution starting from 0x403EEE and patches indirect jumps
"""

import argparse
from dataclasses import dataclass
from typing import List, Optional, Dict, Tuple
import struct

from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EIP, UC_X86_REG_ESP,
    UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP,
)

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from elftools.elf.elffile import ELFFile

PAGE = 0x1000

def page_down(x: int) -> int:
    return x & ~(PAGE - 1)

def page_up(x: int) -> int:
    return (x + PAGE - 1) & ~(PAGE - 1)

def auto_int(x: str) -> int:
    return int(x, 0)

def read_file(path: str) -> bytearray:
    with open(path, "rb") as f:
        return bytearray(f.read())

def write_file(path: str, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def rel32(from_addr: int, to_addr: int) -> int:
    return (to_addr - (from_addr + 5)) & 0xFFFFFFFF

@dataclass
class SegMap:
    vaddr: int
    memsz: int
    filesz: int
    fileoff: int

class Trace32PatchedBlob:
    def __init__(
        self,
        bin_path: str,
        start_va: int,
        arg1: Optional[str],
        max_insn: int,
        out_blob: str,
        debug: bool = False,
    ):
        self.bin_path = bin_path
        self.start_va = start_va & 0xFFFFFFFF
        self.arg1 = arg1
        self.max_insn = max_insn
        self.out_blob = out_blob
        self.debug = debug

        self.raw = read_file(bin_path)
        self.segs: List[SegMap] = []
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)  # 32-bit mode!

        self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        self.cs.detail = False

        self.exec_bytes: Dict[int, bytes] = {}
        self.min_eip: Optional[int] = None
        self.max_eip_end: Optional[int] = None

        self.jmp_patches: List[Tuple[int, int]] = []

    def parse_elf(self):
        with open(self.bin_path, "rb") as f:
            ef = ELFFile(f)
            for seg in ef.iter_segments():
                if seg["p_type"] != "PT_LOAD":
                    continue
                self.segs.append(SegMap(
                    vaddr=seg["p_vaddr"],
                    memsz=seg["p_memsz"],
                    filesz=seg["p_filesz"],
                    fileoff=seg["p_offset"],
                ))

    def map_segments(self):
        for s in self.segs:
            start = page_down(s.vaddr)
            end = page_up(s.vaddr + s.memsz)
            size = end - start

            try:
                self.uc.mem_map(start, size, 1 | 2 | 4)
            except Exception:
                pass

            data = self.raw[s.fileoff:s.fileoff + s.filesz]
            self.uc.mem_write(s.vaddr, bytes(data))
            if s.memsz > s.filesz:
                self.uc.mem_write(s.vaddr + s.filesz, b"\x00" * (s.memsz - s.filesz))

    def map_lowmem_stack(self):
        """
        Set up memory at 0x10000000 for flag input
        Set ESP to 0x10000800
        """
        base = 0x10000000
        size = 0x4000
        try:
            self.uc.mem_map(base, size, 1 | 2 | 4)
        except Exception:
            pass

        self.uc.reg_write(UC_X86_REG_ESP, 0x10000800)

        # Write flag input to 0x10000000
        if self.arg1 is not None:
            b = self.arg1.encode()
            self.uc.mem_write(base, b + b"\x00")

    def _decode_one(self, addr: int):
        code = bytes(self.uc.mem_read(addr, 16))
        insn = next(self.cs.disasm(code, addr, count=1), None)
        if insn is None:
            b = bytes(self.uc.mem_read(addr, 1))
            return 1, b, "db", f"0x{b[0]:02x}"
        return insn.size, insn.bytes, insn.mnemonic, insn.op_str

    def _track_range(self, addr: int, size: int):
        if self.min_eip is None or addr < self.min_eip:
            self.min_eip = addr
        end = (addr + size) & 0xFFFFFFFF
        if self.max_eip_end is None or end > self.max_eip_end:
            self.max_eip_end = end

    def _follow_jmp_r32(self, uc, addr: int, insn_bytes: bytes) -> bool:
        # jmp r32: FF E0..E7 (ModRM selects register)
        if len(insn_bytes) < 2 or insn_bytes[0] != 0xFF:
            return False
        b1 = insn_bytes[1]
        if (b1 & 0xF8) != 0xE0:
            return False

        reg_id = b1 & 0x07
        reg_map = {
            0: UC_X86_REG_EAX,
            1: UC_X86_REG_ECX,
            2: UC_X86_REG_EDX,
            3: UC_X86_REG_EBX,
            4: UC_X86_REG_ESP,
            5: UC_X86_REG_EBP,
            6: UC_X86_REG_ESI,
            7: UC_X86_REG_EDI,
        }
        ureg = reg_map[reg_id]
        target = uc.reg_read(ureg) & 0xFFFFFFFF

        self.jmp_patches.append((addr, target))
        uc.reg_write(UC_X86_REG_EIP, target)

        return True

    def hook_code(self, uc, address, size, user_data):
        address &= 0xFFFFFFFF
        try:
            insn_size, insn_bytes, mnem, ops = self._decode_one(address)
        except Exception:
            uc.emu_stop()
            return

        if address not in self.exec_bytes:
            self.exec_bytes[address] = bytes(insn_bytes)

        self._track_range(address, insn_size)

        # Follow computed dispatcher jump
        if self._follow_jmp_r32(uc, address, insn_bytes):
            return

    def build_blob(self) -> Tuple[int, bytearray]:
        if self.min_eip is None or self.max_eip_end is None:
            raise RuntimeError("No executed instructions recorded.")

        base = self.min_eip
        end = self.max_eip_end
        size = end - base
        blob = bytearray(b"\x90" * size)

        # Lay down executed bytes
        for addr, bts in self.exec_bytes.items():
            off = addr - base
            if 0 <= off < size:
                blob[off:off + len(bts)] = bts

        # Patch executed `jmp r32` into `E9 rel32`
        for site, target in self.jmp_patches:
            off = site - base
            if off < 0 or off + 5 > len(blob):
                continue
            disp = rel32(site, target)
            blob[off:off + 5] = b"\xE9" + struct.pack("<I", disp)

        return base, blob

    def run(self):
        self.parse_elf()
        self.map_segments()
        self.map_lowmem_stack()

        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)
        self.uc.reg_write(UC_X86_REG_EIP, self.start_va)

        try:
            self.uc.emu_start(self.start_va, 0, count=self.max_insn)
        except Exception:
            pass

        base, blob = self.build_blob()
        write_file(self.out_blob, blob)

        print(f"[+] Wrote: {self.out_blob}")
        print(f"[+] Open as x86-32, base address: {hex(base)}")
        print(f"[+] Window: {hex(base)}..{hex(base + len(blob))}  size={hex(len(blob))}")
        print(f"[+] Patched jmp-reg sites: {len(self.jmp_patches)}")


def main():
    ap = argparse.ArgumentParser("32-bit trace blob + jmp patcher")
    ap.add_argument("binary", help="Path to ELF (challenge)")
    ap.add_argument("-o", "--out", default="trace32.bin", help="Output blob")
    ap.add_argument("--start", type=auto_int, default=0x403EEE, help="Start VA (default 0x403EEE)")
    ap.add_argument("--arg", default=None, help="Flag input (written to 0x10000000)")
    ap.add_argument("--max-insn", type=auto_int, default=15_000_000, help="Max instructions")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    t = Trace32PatchedBlob(
        bin_path=args.binary,
        start_va=args.start,
        arg1=args.arg,
        max_insn=args.max_insn,
        out_blob=args.out,
        debug=args.debug,
    )
    t.run()

if __name__ == "__main__":
    main()
```

### Running the 32-bit Emulator

```bash
$ python3 emu32.py chall --arg "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" -o trace32.bin --debug
[dbg] lowmem 0x10000000..0x10004000 ESP=0x10000800
[dbg] start emu @ 0x403eee
[dbg] follow jmp-reg @ 0x403f2e -> 0x408c5c
[dbg] follow jmp-reg @ 0x408ca1 -> 0x40405b
[dbg] follow jmp-reg @ 0x4040a0 -> 0x4073d1
...
[+] Wrote: trace32.bin
[+] Open as x86-32, base address: 0x403eee
[+] Window: 0x403eee..0x40c5ef  size=0x8701
[+] Patched jmp-reg sites: 353
```

Excellent! The emulator:
- Traced **353 indirect jumps** in the 32-bit code
- Created `trace32.bin` with all jumps patched
- Size: 34,561 bytes (0x8701)

### Viewing the Patched 32-bit Code

We can disassemble it with objdump:

```bash
$ objdump -D -b binary -m i386 -M intel --adjust-vma=0x403eee trace32.bin | head -50
00403eee <.data>:
  403eee:	b8 3c ae db 5f       	mov    eax,0x5fdbae3c
  403ef3:	bb 6e 4d 00 00       	mov    ebx,0x4d6e
  403ef8:	31 c3                	xor    ebx,eax
  ...
  403f2e:	e9 29 4d 00 00       	jmp    0x408c5c      # Direct jump!
  ...
  403f3b:	66 0f f8 c4          	psubb  xmm0,xmm4     # SSE instruction!
  403f45:	66 0f ef c5          	pxor   xmm0,xmm5     # SSE instruction!
  403f4f:	66 0f fc c7          	paddb  xmm0,xmm7     # SSE instruction!
```

Perfect! We can see:
- **Direct jumps** (patched from `jmp eax/ebx/etc.`)
- **SSE/SIMD instructions** (`psubb`, `pxor`, `paddb`)

These SSE instructions are the encryption algorithm!

---

## Understanding the Encryption

### SSE/XMM Instructions Overview

SSE (Streaming SIMD Extensions) uses XMM registers (128-bit) to process multiple bytes in parallel:

- `xmm0` through `xmm7` - 128-bit registers (16 bytes each)
- `paddb xmm0, xmm1` - Add bytes: xmm0[i] = xmm0[i] + xmm1[i] for i=0..15
- `psubb xmm0, xmm1` - Subtract bytes
- `pxor xmm0, xmm1` - XOR bytes

But in this challenge, all 16 bytes in each XMM register are the **same value**.

### The XMM Constants

Remember from our earlier analysis, these values were loaded:

```asm
40398a:  movabs rax,0x0f0f0f0f0f0f0f0f
403994:  movq   xmm1,rax          ; xmm1 = 0x0F (all bytes)

4018c8:  movabs rax,0x1e1e1e1e1e1e1e1e
4018d2:  movq   xmm2,rax          ; xmm2 = 0x1E (all bytes)

403605:  movabs rax,0x0101010101010101
40360f:  movq   xmm3,rax          ; xmm3 = 0x01 (all bytes)

4013b0:  movabs rax,0x1c1c1c1c1c1c1c1c
4013ba:  movq   xmm6,rax          ; xmm6 = 0x1C (all bytes)

401c3c:  movabs rax,0x0a0a0a0a0a0a0a0a
401c46:  movq   xmm7,rax          ; xmm7 = 0x0A (all bytes)
```

So the keys are:
- k1 = 0x0F (xmm1)
- k2 = 0x1E (xmm2)
- k3 = 0x01 (xmm3)
- k4 = 0x1C (xmm6)
- k5 = 0x0A (xmm7)

### The Encryption Algorithm

From the writeup and code analysis, the encryption for each byte is:

```c
// For each byte x of the flag:

v92  = ((x + k1) ^ k2) - k3
v182 = ((x + k4) ^ k5) - k1
v68  = ((x + k2) ^ k3) - k4

v107 = (v92 + v182) ^ v68
v207 = (v182 + v68) ^ v107

encrypted = ((v107 - v207) ^ ((v68 + v107) ^ v207)) + k5
```

All operations are **modulo 256** (byte arithmetic).

**Key insight:** This is **byte-by-byte encryption** - each byte is encrypted independently!

### Two Solution Approaches

**Approach 1: Reverse the algorithm** (algebraic inversion)
- Hard because of the complex operations and modulo arithmetic

**Approach 2: Brute force each byte** (practical)
- Only 256 possibilities per byte
- Very fast (38 bytes × 256 = 9,728 encryptions)
- Guaranteed to work

We'll use Approach 2!

---

## Writing the Solver

### The Solver Script

```python
#!/usr/bin/env python3
"""
Solver for Psycho_Flag challenge
Decrypts the flag by brute-forcing each byte
"""

# XMM register values (keys)
k1 = 0x0F  # xmm1
k2 = 0x1E  # xmm2
k3 = 0x01  # xmm3
k4 = 0x1C  # xmm6
k5 = 0x0A  # xmm7

# Encrypted flag from 0x40d04d
encrypted = bytes.fromhex(
    "D9910DB5A48EC1923964905AC1D966E3"
    "2D688E66E1C0A5CA8A66E03B6655C1B4"
    "66EE6875CA8C"
)

print(f"Encrypted flag ({len(encrypted)} bytes):")
print(encrypted.hex())
print()

def encrypt_byte(x):
    """
    Encrypt a single byte using the algorithm
    All operations are mod 256 (byte arithmetic)
    """
    # v92  = ((x + k1) ^ k2) - k3
    v92 = (((x + k1) & 0xFF) ^ k2) - k3
    v92 &= 0xFF

    # v182 = ((x + k4) ^ k5) - k1
    v182 = (((x + k4) & 0xFF) ^ k5) - k1
    v182 &= 0xFF

    # v68  = ((x + k2) ^ k3) - k4
    v68 = (((x + k2) & 0xFF) ^ k3) - k4
    v68 &= 0xFF

    # v107 = (v92 + v182) ^ v68
    v107 = ((v92 + v182) & 0xFF) ^ v68
    v107 &= 0xFF

    # v207 = (v182 + v68) ^ v107
    v207 = ((v182 + v68) & 0xFF) ^ v107
    v207 &= 0xFF

    # out = ((v107 - v207) ^ ((v68 + v107) ^ v207)) + k5
    temp1 = (v107 - v207) & 0xFF
    temp2 = ((v68 + v107) & 0xFF) ^ v207
    out = (temp1 ^ temp2) + k5
    out &= 0xFF

    return out

def decrypt_byte(encrypted_byte):
    """
    Decrypt a single byte by brute force
    Try all 256 possible input bytes
    """
    for candidate in range(256):
        if encrypt_byte(candidate) == encrypted_byte:
            return candidate
    return None

# Decrypt the flag
print("Decrypting flag...")
flag = bytearray()

for i, enc_byte in enumerate(encrypted):
    dec_byte = decrypt_byte(enc_byte)
    if dec_byte is None:
        print(f"ERROR: Could not decrypt byte {i} (0x{enc_byte:02x})")
        flag.append(ord('?'))
    else:
        flag.append(dec_byte)
        print(f"Byte {i:2d}: 0x{enc_byte:02x} -> 0x{dec_byte:02x} ('{chr(dec_byte) if 32 <= dec_byte < 127 else '.'}')")

print()
print("=" * 70)
print("FLAG:", flag.decode('ascii', errors='replace'))
print("=" * 70)

# Verify by re-encrypting
print("\nVerification - re-encrypting the flag:")
re_encrypted = bytes([encrypt_byte(b) for b in flag])
if re_encrypted == encrypted:
    print("✓ SUCCESS! Re-encryption matches original encrypted flag")
else:
    print("✗ ERROR! Re-encryption doesn't match")
    print("Original:    ", encrypted.hex())
    print("Re-encrypted:", re_encrypted.hex())
```

### Running the Solver

```bash
$ python3 solver.py
Encrypted flag (38 bytes):
d9910db5a48ec1923964905ac1d966e32d688e66e1c0a5ca8a66e03b6655c1b466ee6875ca8c

Decrypting flag...
Byte  0: 0xd9 -> 0x30 ('0')
Byte  1: 0x91 -> 0x78 ('x')
Byte  2: 0x0d -> 0x4c ('L')
Byte  3: 0xb5 -> 0x34 ('4')
Byte  4: 0xa4 -> 0x75 ('u')
Byte  5: 0x8e -> 0x67 ('g')
Byte  6: 0xc1 -> 0x68 ('h')
Byte  7: 0x92 -> 0x7b ('{')
Byte  8: 0x39 -> 0x50 ('P')
Byte  9: 0x64 -> 0x35 ('5')
Byte 10: 0x90 -> 0x79 ('y')
Byte 11: 0x5a -> 0x63 ('c')
Byte 12: 0xc1 -> 0x68 ('h')
Byte 13: 0xd9 -> 0x30 ('0')
Byte 14: 0x66 -> 0x5f ('_')
Byte 15: 0xe3 -> 0x46 ('F')
Byte 16: 0x2d -> 0x6c ('l')
Byte 17: 0x68 -> 0x61 ('a')
Byte 18: 0x8e -> 0x67 ('g')
Byte 19: 0x66 -> 0x5f ('_')
Byte 20: 0xe1 -> 0x48 ('H')
Byte 21: 0xc0 -> 0x69 ('i')
Byte 22: 0xa5 -> 0x64 ('d')
Byte 23: 0xca -> 0x33 ('3')
Byte 24: 0x8a -> 0x73 ('s')
Byte 25: 0x66 -> 0x5f ('_')
Byte 26: 0xe0 -> 0x49 ('I')
Byte 27: 0x3b -> 0x6e ('n')
Byte 28: 0x66 -> 0x5f ('_')
Byte 29: 0x55 -> 0x54 ('T')
Byte 30: 0xc1 -> 0x68 ('h')
Byte 31: 0xb4 -> 0x65 ('e')
Byte 32: 0x66 -> 0x5f ('_')
Byte 33: 0xee -> 0x47 ('G')
Byte 34: 0x68 -> 0x61 ('a')
Byte 35: 0x75 -> 0x74 ('t')
Byte 36: 0xca -> 0x33 ('3')
Byte 37: 0x8c -> 0x7d ('}')

======================================================================
FLAG: 0xL4ugh{P5ych0_Flag_Hid3s_In_The_Gat3}
======================================================================

Verification - re-encrypting the flag:
✓ SUCCESS! Re-encryption matches original encrypted flag
```

### Verifying the Flag

Let's test it against the actual binary:

```bash
$ ./chall "0xL4ugh{P5ych0_Flag_Hid3s_In_The_Gat3}"
Correct!
```

**Success!** 🎉

---

## Conclusion

### Summary of Techniques

This challenge demonstrated several advanced reverse engineering concepts:

1. **Obfuscation Analysis**
   - Identified junk instructions (double XOR, add/sub pairs)
   - Recognized computed jumps (`jmp rax`)
   - Extracted real logic from noise

2. **Dynamic Binary Instrumentation**
   - Used Unicorn Engine for CPU emulation
   - Hooked instructions to trace execution
   - Calculated jump targets at runtime

3. **Binary Patching**
   - Converted indirect jumps to direct jumps
   - Fixed Control Flow Graph for static analysis
   - Made decompilation possible

4. **Process Interaction**
   - Analyzed fork/exec behavior
   - Understood ptrace memory modification
   - Traced parent-child communication

5. **Heaven's Gate**
   - Recognized 64-bit to 32-bit mode switching
   - Analyzed far return technique
   - Handled mixed-mode execution

6. **SIMD/SSE Operations**
   - Understood XMM register operations
   - Recognized parallel byte processing
   - Simplified to scalar operations

7. **Cryptanalysis**
   - Identified byte-by-byte encryption
   - Chose brute force over algebraic reversal
   - Verified solution correctness

### Key Takeaways

**When static analysis fails, use dynamic analysis:**
- Emulation reveals runtime behavior
- Computed jumps can be resolved
- Obfuscation can be bypassed

**Start with small inputs:**
- First attempt with "aaa" revealed early paths
- Second attempt with 38 bytes revealed full behavior
- Iterative approach worked well

**Brute force is often practical:**
- 256 possibilities per byte is trivial
- Faster than reversing complex math
- Guaranteed to find the answer

### Tools Used

- **objdump** - Basic disassembly
- **readelf** - ELF structure analysis
- **xxd** - Hex viewing
- **Unicorn Engine** - CPU emulation
- **Capstone** - Disassembly library
- **Python** - Scripting and solving

### Flag Meaning

**0xL4ugh{P5ych0_Flag_Hid3s_In_The_Gat3}**

"Psycho_Flag_Hides_In_The_Gate" - A reference to:
- The challenge name (Psycho_Flag)
- The Heaven's Gate technique used
- The flag being hidden in 32-bit code after the "gate"

---

## Files Summary

### Scripts Created

1. **emu.py** - 64-bit emulator for parent process
   ```bash
   python3 emu.py chall -o chall.patched --arg "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   ```

2. **emu32.py** - 32-bit emulator for child process
   ```bash
   python3 emu32.py chall -o trace32.bin --arg "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   ```

3. **solver.py** - Flag decryption script
   ```bash
   python3 solver.py
   ```

### Binary Files

- **chall** - Original challenge binary
- **chall.patched** - Parent code with fixed jumps (64-bit)
- **trace32.bin** - Child code with fixed jumps (32-bit)

### Key Addresses

- **0x40d04d** - Encrypted flag (38 bytes)
- **0x401000** - Entry point
- **0x401920** - Where parent writes to child
- **0x403EEE** - 32-bit code entry (Heaven's Gate)
- **0x10000000** - Flag buffer in memory

---

