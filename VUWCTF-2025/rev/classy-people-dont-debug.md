---
ctf: VUWCTF 2025
category: rev
difficulty: hard
points: 400
flag: "VuwCTF{very_classy_d0'nt_6ou_s33}"
techniques: [anti-debugging, ptrace, sha256_integrity, watchdog_process]
tools: [ghidra, python]
---

# Classy People Dont Debug

## Description
A stripped ELF binary with heavy anti-debugging that prompts for a flag and checks if it's correct.

## Solution

### Anti-Debugging Techniques

1. ptrace self-trace
2. Watchdog process checking TracerPid
3. Memory map inspection for Frida/ASan
4. Parent process check for debuggers
5. Timing checks
6. VM detection
7. Code integrity check (SHA256)

### Understanding sub_402f88

The function applies a triple-XOR decryption:

```python
val1 = (193 + i * 13) & 0xFF  # 0xC1 + i*0xD
val2 = (163 + i * 5) & 0xFF   # 0xA3 + i*0x5
val3 = data_404120[i % 64]
result = lookup_val ^ val1 ^ val2 ^ val3
```

### Solution Script

```python
with open('Classy', 'rb') as f:
    f.seek(0x4120)
    data_404120 = f.read(64)
    f.seek(0x4180)
    data_404180 = f.read(200)

flag = []
for i in range(33):
    lookup_val = data_404180[i * 6]
    val1 = (193 + i * 13) & 0xFF
    val2 = (163 + i * 5) & 0xFF
    val3 = data_404120[i % 64]
    char = lookup_val ^ val1 ^ val2 ^ val3
    flag.append(chr(char))

print(''.join(flag))
```

## Key Techniques
- Anti-debugging bypass techniques
- ptrace detection and evasion
- Watchdog process analysis
- Memory mapping analysis
- SHA256 integrity check bypassing
- Static analysis of heavily obfuscated code
