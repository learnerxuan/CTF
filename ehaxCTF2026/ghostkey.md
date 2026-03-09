# ghostkey — CTF Reverse Engineering Writeup

**Challenge:** ghostkey  
**Category:** Reverse Engineering  
**Flag:** `crackme{AES_gh0stk3y_r3v3rs3d!!}`  
**Key:** `Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!`  

---

## Table of Contents

1. [Phase 0 — Recon](#phase-0--recon)
2. [Phase 1 — Deep Static Analysis](#phase-1--deep-static-analysis)
3. [Understanding the Checks (Beginner Guide)](#understanding-the-checks)
   - [Bytes, Hex, and ASCII](#bytes-hex-and-ascii)
   - [XOR — The Hacker's Tool](#xor--the-hackers-tool)
   - [Check 1: Length](#check-1-length)
   - [Check 2: Printable ASCII](#check-2-printable-ascii)
   - [Check 3: LFSR / CRC-16](#check-3-lfsr--crc-16)
   - [Check 4: Nibble XOR](#check-4-nibble-xor)
   - [Check 5: Column Sums](#check-5-column-sums)
   - [Check 6: Pair Constraints](#check-6-pair-constraints)
   - [Check 7: S-Box XOR](#check-7-s-box-xor)
   - [Check 8: Tag XOR](#check-8-tag-xor)
   - [Check 9: AES Decrypt](#check-9-aes-decrypt)
4. [Phase 2 — Solve Strategy](#phase-2--solve-strategy)
5. [Phase 3 — The Solver](#phase-3--the-solver)
6. [Phase 4 — Getting the Flag](#phase-4--getting-the-flag)
7. [Key Lessons and Mistakes](#key-lessons-and-mistakes)

---

## Phase 0 — Recon

### File Identification

```bash
ls -la
# -rwxrwxr-x 1 xuan xuan 2543639 Feb 28 22:01 ghost

file ghost
# ghost: ELF 64-bit LSB executable, x86-64, statically linked, not stripped

checksec --file=ghost
# No RELRO, No canary, NX enabled, No PIE
# 2614 Symbols — NOT STRIPPED (goldmine for reversing)
```

Not stripped means all function and variable names are preserved. This is rare and extremely helpful.

### Running the Binary

```bash
./ghost
# (nothing — needs argument)

./ghost test
# [-] Check failed: length

./ghost AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   # 32 A's
# [-] Check failed: lfsr
# Wrong key. Keep reversing.

./ghost "Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!"
# [+] All checks passed!
# [+] Flag: crackme{AES_gh0stk3y_r3v3rs3d!!}
```

**Key observation:** The program accepts `argv[1]`. It needs exactly 32 characters. Multiple named checks fail in sequence — this is a multi-gate crackme.

### Strings Search

```bash
strings ghost | grep -iE "flag|correct|success|wrong|invalid|check"
# [+] Flag: %s
# [-] Check failed: %s
# [+] All checks passed!
# Wrong key. Keep reversing.
# [-] Check failed: aes_verify
# [-] Check failed: lfsr
```

### Symbol Table (Because It's Not Stripped)

```bash
nm ghost | grep "main\."
```

Output reveals everything:
```
0000000000498e60 T main.aesCheck
0000000000499aa0 T main.main.func1     ← check 1
0000000000499a20 T main.main.func2     ← check 2
0000000000499960 T main.main.func3     ← check 3 (lfsr)
0000000000499920 T main.main.func4     ← check 4 (nibble)
0000000000499880 T main.main.func5     ← check 5 (colsum)
0000000000499780 T main.main.func6     ← check 6 (pairs)
0000000000499740 T main.main.func7     ← check 7 (sbox)
0000000000499700 T main.main.func8     ← check 8 (tag)
0000000000498d40 T main.tagCheck
000000000058e560 D main.encryptedFlag  ← encrypted flag bytes
000000000058e210 d main..gobytes.1     ← "crackme{" prefix
0000000000595be0 D main.flagPrefix
0000000000595bc0 D main.pairs          ← pair constraint data
000000000058ee40 D main.sbox           ← AES S-box
000000000058e218 D main.targetColSums
000000000058e1c4 D main.targetLFSR
000000000058e1c8 D main.targetNibble
000000000058e220 D main.targetTag
```

**Classification:** Go binary, statically linked, multi-constraint crackme. 9 sequential checks on a 32-character key.

### Extract All Data from Binary

The binary has a `.noptrdata` section (addr `0x58e1c0`, file offset `0x18e1c0`) and `.data` section (addr `0x595800`, file offset `0x195800`). All targets are stored there.

```bash
readelf -S ghost | grep -E "noptrdata|\.data"
# .noptrdata  addr=0x58e1c0  offset=0x18e1c0
# .data       addr=0x595800  offset=0x195800
```

```python
# extract_data.py — read all targets from binary
import struct

with open("ghost", "rb") as f:
    data = f.read()

def noptrdata(vaddr, size):
    off = 0x18e1c0 + (vaddr - 0x58e1c0)
    return data[off:off+size]

# targetLFSR @ 0x58e1c4 (2 bytes, little-endian)
b = noptrdata(0x58e1c4, 2)
print(f"targetLFSR:    0x{struct.unpack('<H', b)[0]:04X}")   # 0x4358

# targetNibble @ 0x58e1c8 (4 bytes)
b = noptrdata(0x58e1c8, 4)
print(f"targetNibble:  {list(b)}")                            # [8, 8, 4, 7]

# targetColSums @ 0x58e218 (8 bytes, signed)
b = noptrdata(0x58e218, 8)
print(f"targetColSums: {[struct.unpack('b', bytes([x]))[0] for x in b]}")
# [12, 39, 8, 0, 55, 33, 50, 96]

# targetTag @ 0x58e220 (8 bytes)
b = noptrdata(0x58e220, 8)
print(f"targetTag:     {[hex(x) for x in b]}")
# [0x6c, 0x75, 0x3a, 0x01, 0x7e, 0x2f, 0x34, 0x00]

# flagPrefix @ 0x58e210 (8 bytes)
b = noptrdata(0x58e210, 8)
print(f"flagPrefix:    {b}")                                   # b'crackme{'

# encryptedFlag @ 0x58e560 (32 bytes)
b = noptrdata(0x58e560, 32)
print(f"encryptedFlag: {b.hex()}")
# 0037a8858c84fd73233ee93571d82bde4f1846e81241af6df95ed4bd156a8999

# sbox @ 0x58ee40 (256 bytes)
b = noptrdata(0x58ee40, 256)
print(f"sbox: {b.hex()}")
```

For the `pairs` data, the `.data` section contains a Go slice header (pointer + length + capacity). The pointer `0x58f3a0` points into `.noptrdata`:

```python
# pairs slice header at 0x595bc0:
# ptr=0x58f3a0, len=12, cap=12
# Each entry: index1(8 bytes) + index2(8 bytes) + mod(1 byte) + rem(1 byte) + pad(6 bytes) = 24 bytes

pairs_data = noptrdata(0x58f3a0, 12 * 24)
pairs = []
for i in range(12):
    entry = pairs_data[i*24:(i+1)*24]
    idx1  = struct.unpack('<Q', entry[0:8])[0]
    idx2  = struct.unpack('<Q', entry[8:16])[0]
    mod   = entry[16]
    rem   = entry[17]
    pairs.append((idx1, idx2, mod, rem))
    print(f"  key[{idx1}] + key[{idx2}] ≡ {rem} (mod {mod})")
```

Output:
```
key[0]  + key[31] ≡ 104 (mod 127)
key[3]  + key[28] ≡  17 (mod 131)
key[7]  + key[24] ≡  53 (mod 113)
key[11] + key[20] ≡  58 (mod 109)
key[1]  + key[15] ≡  52 (mod 103)
key[5]  + key[27] ≡  88 (mod  97)
key[9]  + key[22] ≡  20 (mod 107)
key[13] + key[18] ≡  64 (mod 101)
key[2]  + key[29] ≡  81 (mod 127)
key[6]  + key[25] ≡ 118 (mod 131)
key[10] + key[21] ≡  40 (mod 113)
key[14] + key[17] ≡  83 (mod 109)
```

---

## Phase 1 — Deep Static Analysis

### Disassembly Setup

```bash
# Open in Ghidra (GUI) or use objdump for quick look
objdump -d ghost | grep -A 50 "<main.main>"

# For dynamic analysis, use GDB with pwndbg
gdb ./ghost
```

### Dynamic Analysis with pwndbg

```bash
gdb ./ghost
# Inside GDB:

# Set up to run with the key
pwndbg> set args "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# Find function addresses (binary not stripped, so by name)
pwndbg> info address main.main
# Symbol "main.main" is at 0x4990a0

pwndbg> info address main.aesCheck
# Symbol "main.aesCheck" is at 0x498e60

# Set breakpoints on each check function
pwndbg> b main.main.func3    # LFSR check
pwndbg> b main.main.func4    # nibble check
pwndbg> b main.main.func5    # colsum check
pwndbg> b main.main.func6    # pairs check
pwndbg> b main.main.func7    # sbox check
pwndbg> b main.main.func8    # tag check
pwndbg> b main.aesCheck      # final AES check

pwndbg> run

# When stopped at aesCheck, inspect the key being processed:
pwndbg> x/32c $rax            # print 32 characters from RAX (key pointer in Go)
pwndbg> x/32xb $rax           # same in hex bytes

# Check what the LFSR target is in memory:
pwndbg> x/2xb 0x58e1c4        # targetLFSR = 0x4358

# Check encrypted flag:
pwndbg> x/32xb 0x58e560

# Inspect stack at aesCheck to see SHA256/MD5 calls:
pwndbg> disassemble main.aesCheck
# Look for calls to crypto_sha256_Sum256 and crypto_md5_Sum
# Note: the disasm shows which slice of key is passed to each hash

# To confirm key slice for SHA256 (first 16 bytes):
pwndbg> b crypto/sha256.Sum256
pwndbg> c
pwndbg> x/16c $rax             # confirm it's "Gh0stK3y-R3v3rs3" (first 16)

# To confirm key slice for MD5 (last 16 bytes):
pwndbg> b crypto/md5.Sum
pwndbg> c
pwndbg> x/16c $rax             # confirm it's "-M3-1f-U-C4n!!!!" (last 16)
```

> **Why dynamic analysis matters:** The Ghidra decompilation of Go code is messy.
> Static reading alone led to a mistake — I assumed SHA256 and MD5 both operated
> on the full key. Dynamic analysis confirmed they operate on different halves.

### Program Flow (Decompiled Logic)

**main.main** sets up 8 check functions in a loop. Each function takes the key as argument and returns true/false. If any returns false, prints `[-] Check failed: <name>` and exits. After all 8 pass, calls `main.aesCheck`.

```
main.main:
  if argc != 2: print usage, exit
  if len(argv[1]) != 32: fail "length"

  checks = [func1, func2, func3, func4, func5, func6, func7, func8]
  names  = ["length", "charset", "lfsr", "nibble", "colsum", "pairs", "sbox", "tag"]

  for each check:
      if check(key) == false:
          print "[-] Check failed: <name>"
          exit

  if aesCheck(key) == false:
      print "Wrong key. Keep reversing."
  else:
      print "[+] All checks passed!"
      print "[+] Flag: <decrypted>"
```

---

## Understanding the Checks

### Bytes, Hex, and ASCII

> **Beginner note:** Everything in computers is bytes. A byte is a number from 0–255.
> Characters are just numbers with a name.

```
Character:  G    h    0    s    !    space
Decimal:    71   104  48   115  33   32
Hex:        47   68   30   73   21   20
```

Hex (hexadecimal) uses digits 0–9 and A–F. One byte = exactly 2 hex digits.
```
255 decimal = FF hex
65  decimal = 41 hex  ('A')
```

---

### XOR — The Hacker's Tool

XOR (eXclusive OR) compares two bits: **same → 0, different → 1**.

```
0 XOR 0 = 0
0 XOR 1 = 1
1 XOR 0 = 1
1 XOR 1 = 0
```

On real bytes (all 8 bits at once):
```
'G' = 71  = 0100 0111
'h' = 104 = 0110 1000
XOR:      = 0010 1111 = 47
```

**The superpower of XOR:**
```
A XOR B = C  →  C XOR B = A   (XOR is its own inverse)
A XOR A = 0                    (anything XOR itself = 0)
A XOR 0 = A                    (XOR with 0 does nothing)
```

This last property explains why four identical `!` XOR together = 0:
```
'!' XOR '!' = 0
  0 XOR '!' = '!'
'!' XOR '!' = 0
```
Used everywhere: tag check, nibble check, sbox check, and internally in AES.

---

### Check 1: Length

```python
# func1 decompiled:
return len(key) == 32
```

The key must be exactly 32 characters. Simple gate. In Z3:
```python
# Already guaranteed by creating exactly 32 variables
k = [BitVec(f'k{i}', 8) for i in range(32)]
```

---

### Check 2: Printable ASCII

```python
# func2 decompiled:
for char in key:
    assert 0x20 <= char <= 0x7E
```

Every character must be typeable — letters, numbers, symbols. No invisible control characters like newline (`\n` = 10) or null (`\0` = 0).

```
0x20 = 32  = space (lowest printable)
0x7E = 126 = '~'  (highest printable)
```

In Z3:
```python
for x in k:
    s.add(x >= 0x20, x <= 0x7E)
```

---

### Check 3: LFSR / CRC-16

> **Beginner explanation:** LFSR stands for Linear Feedback Shift Register. Forget
> the name. Think of it as a **fingerprint machine**. It processes every bit of your
> key and produces a 16-bit number. Change even one character → completely different
> fingerprint. Like a checksum.

**The algorithm:**
```python
state = 0xACE1   # starting value (16-bit)
POLY  = 0xB400   # the "feedback" constant

for each byte in key:
    for each of the 8 bits in that byte:
        lsb = (byte XOR state) & 1    # look at the lowest bit
        state = state >> 1             # shift state right
        byte  = byte  >> 1             # shift byte right
        if lsb == 1:
            state = state XOR 0xB400  # apply feedback

final state must equal 0x4358
```

**Verification:**
```python
key = b"Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!"
state = 0xACE1
for byte in key:
    b = byte
    for _ in range(8):
        lsb = (b ^ state) & 1
        state >>= 1
        b >>= 1
        if lsb: state ^= 0xB400
print(hex(state))   # 0x4358 ✓
```

**Avalanche effect:** Change `G` → `H` (one character):
```
Correct key: LFSR = 0x4358
Changed key: LFSR = 0x23B6   ← completely different!
```
Small input change → huge output change. This is what makes CRC useful as a checksum.

**Why this was hard for Z3 (and the fix):**

Z3 needs to work backwards — find 32 characters that produce state `0x4358`. The LFSR has 32 × 8 = 256 bit-processing steps.

**Wrong encoding (slow — caused Z3 timeout):**
```python
st = If(lsb != 0, st ^ BitVecVal(0xB400, 16), st)
# Creates a BRANCH at every step
# 256 branches → 2^256 paths → Z3 gives up
```

**Correct encoding (fast — the trick):**
```python
lsb  = (state ^ ZeroExt(8, byte_bit)) & BitVecVal(1, 16)
mask = -lsb     # if lsb=1: -1 = 0xFFFF; if lsb=0: -0 = 0x0000
state = LShR(state, 1) ^ (BitVecVal(0xB400, 16) & mask)
# NO branch — pure arithmetic
# 0xB400 & 0xFFFF = 0xB400 (apply XOR)
# 0xB400 & 0x0000 = 0x0000 (skip XOR)
# Z3 solves this as algebra, not tree search
```

Both produce identical results. The mask trick converts an `if` statement into a multiply/AND operation — which Z3 handles in the bitvector arithmetic domain without branching.

---

### Check 4: Nibble XOR

> **Beginner explanation:** A nibble is half a byte — 4 bits. Every byte has a high
> nibble (top 4 bits) and a low nibble (bottom 4 bits).

```
Byte 'G' = 0x47 = 0100 0111
                  ^^^^ ^^^^
                  high  low
                  = 4    = 7

high nibble = byte >> 4       (shift right 4 positions)
low  nibble = byte &  0x0F    (keep only bottom 4 bits)
```

**The algorithm:** Split 32 bytes into 4 groups of 8. For each group, XOR all `(high_nibble XOR low_nibble)` values together.

```python
target_nibble = [8, 8, 4, 7]

for group in range(4):
    acc = 0
    for j in range(8):
        b    = key[group*8 + j]
        high = b >> 4
        low  = b & 0x0F
        acc ^= (high ^ low)
    assert acc == target_nibble[group]
```

**Verification on real key:**
```
Group 0 (bytes 0-7):  3^14^3^4^3^15^0^14 = 8  ✓
Group 1 (bytes 8-15): 15^7^0^1^0^5^4^0   = 8  ✓
Group 2 (bytes 16-23): 15^9^0^15^2^0^15^0 = 4  ✓
Group 3 (bytes 24-31): 15^7^7^8^3^3^3^3  = 7  ✓
```

---

### Check 5: Column Sums

Think of the 32 bytes as a **4 rows × 8 columns grid**:

```
Row 0: G  h  0  s  t  K  3  y    (bytes  0- 7)
Row 1: -  R  3  v  3  r  s  3    (bytes  8-15)
Row 2: -  M  3  -  1  f  -  U    (bytes 16-23)
Row 3: -  C  4  n  !  !  !  !    (bytes 24-31)
       ↑  ↑  ↑  ↑  ↑  ↑  ↑  ↑
      c0 c1 c2 c3 c4 c5 c6 c7
```

**The rule:** For each column, add all 4 values. The remainder when dividing by 97 must equal the target.

```python
target_col = [12, 39, 8, 0, 55, 33, 50, 96]

for col in range(8):
    total = key[col] + key[col+8] + key[col+16] + key[col+24]
    assert total % 97 == target_col[col]
```

> **What is modulo (%):** Remainder after division. Like a clock:
> - 13 % 12 = 1 (clock wraps at 12)
> - 206 % 97 = 12 (97 fits twice into 206, leftover = 206 − 194 = 12)

**Verification:**
```
Col 0: G(71) + -(45) + -(45) + -(45) = 206   206 % 97 = 12  ✓
Col 1: h(104) + R(82) + M(77) + C(67) = 330  330 % 97 = 39  ✓
Col 7: y(121) + 3(51) + U(85) + !(33) = 290  290 % 97 = 96  ✓
```

In Z3, modulo is `URem` (unsigned remainder):
```python
for col in range(8):
    col_sum = ZeroExt(8,k[col]) + ZeroExt(8,k[col+8]) + ZeroExt(8,k[col+16]) + ZeroExt(8,k[col+24])
    s.add(URem(col_sum, BitVecVal(97, 16)) == target_col[col])
```

---

### Check 6: Pair Constraints

12 rules, each involving two key positions:

```python
pairs = [
    (0,  31, 127, 104),  # key[0]  + key[31] ≡ 104 (mod 127)
    (3,  28, 131,  17),  # key[3]  + key[28] ≡  17 (mod 131)
    (7,  24, 113,  53),  # key[7]  + key[24] ≡  53 (mod 113)
    (11, 20, 109,  58),
    (1,  15, 103,  52),
    (5,  27,  97,  88),
    (9,  22, 107,  20),
    (13, 18, 101,  64),
    (2,  29, 127,  81),
    (6,  25, 131, 118),
    (10, 21, 113,  40),
    (14, 17, 109,  83),
]
```

**Verification:**
```
key[0]+key[31]:  G(71) + !(33) = 104    104 % 127 = 104  ✓
key[3]+key[28]:  s(115) + !(33) = 148   148 % 131 =  17  ✓
key[7]+key[24]:  y(121) + -(45) = 166   166 % 113 =  53  ✓
```

> **Note on prime moduli (97, 101, 103, 107, 109, 113, 127, 131):** Using prime
> numbers as divisors makes modular equations harder to reverse, since primes don't
> share factors with other numbers.

---

### Check 7: S-Box XOR

> **Beginner explanation:** An S-Box (Substitution Box) is a lookup table. Every byte
> maps to a different byte — like a secret codebook. The AES S-Box is the standard
> cryptographic one used in AES encryption worldwide.

```
sbox[0x00] = 0x63
sbox[0x47] = 0xA0   ← 'G' maps to 0xA0
sbox[0x21] = 0xFD   ← '!' maps to 0xFD
```

**The rule:** Take key positions 0, 2, 4, ..., 30 (every other position). Look each up in the S-Box. XOR all results. Must equal 0x66.

```python
acc = 0
for i in range(0, 32, 2):    # positions: 0, 2, 4, 6, ..., 30
    acc ^= sbox[key[i]]
assert acc == 0x66
```

**Step-by-step on real key:**
```
pos  0: 'G'(0x47) → sbox[0x47] = 0xA0   running XOR = 0xA0
pos  2: '0'(0x30) → sbox[0x30] = 0x04   running XOR = 0xA4
pos  4: 't'(0x74) → sbox[0x74] = 0x92   running XOR = 0x36
...
pos 26: '4'(0x34) → sbox[0x34] = 0x18   running XOR = 0x66
pos 28: '!'(0x21) → sbox[0x21] = 0xFD   running XOR = 0x9B
pos 30: '!'(0x21) → sbox[0x21] = 0xFD   running XOR = 0x66  ✓
```

Positions 28 and 30 are both `'!'` → same sbox output → XOR cancels → back to 0x66.

**Why S-Box was hard for Z3 (and the fix):**

Wrong encoding (256-level if-else chain):
```python
result = If(byte == 0, 0x63, If(byte == 1, 0x7c, If(...)))  # 256 deep
```

Correct encoding (Z3 Array theory — designed for lookup tables):
```python
SBOX = Array('SBOX', BitVecSort(8), BitVecSort(8))
for i, val in enumerate(sbox):
    s.add(Select(SBOX, BitVecVal(i, 8)) == BitVecVal(val, 8))

# Lookup:
result = Select(SBOX, k[i])
```

However, this was **left out of Z3 entirely** in the final working solution, and verified in Python instead — because combining S-Box Array theory with `URem` (modular arithmetic) still caused Z3 to timeout. The key insight: with LFSR properly constraining the search, only ~5 solutions exist before finding one that also passes the S-Box check.

---

### Check 8: Tag XOR

Divide 32 bytes into 8 groups of 4. Each group must XOR to its target:

```python
target_tag = [0x6C, 0x75, 0x3A, 0x01, 0x7E, 0x2F, 0x34, 0x00]

for i in range(8):
    a = 4 * i
    assert key[a] ^ key[a+1] ^ key[a+2] ^ key[a+3] == target_tag[i]
```

**Verification:**
```
Group 0: G(71) ^ h(104) ^ 0(48) ^ s(115) = 108 = 0x6C  ✓
Group 7: !(33) ^ !(33)  ^ !(33) ^ !(33)  =   0 = 0x00  ✓
```

Group 7 = four identical `!` values → XOR cancels → 0. Target for group 7 is 0x00.

---

### Check 9: AES Decrypt

The final boss check. The binary stores a 32-byte encrypted blob. With the correct key, it must decrypt to start with `crackme{`.

**How it works:**

```
Your 32-char key split in half:
   "Gh0stK3y-R3v3rs3"     "-M3-1f-U-C4n!!!!"
   ↓ SHA256 (32 bytes)     ↓ MD5 (16 bytes)
   AES-256 key             AES IV (Initialization Vector)

AES-256-CBC-Decrypt(encrypted_blob, key=SHA256_result, iv=MD5_result)
→ b"crackme{AES_gh0stk3y_r3v3rs3d!!}"
```

> **What is SHA256/MD5:** Hash functions — any input produces a fixed-size fingerprint.
> One-way: you can compute the hash, but not reverse it.
> SHA256 always outputs 32 bytes. MD5 always outputs 16 bytes.

> **What is an IV:** In AES-CBC mode, each 16-byte block is XORed with the previous
> block before encryption. The IV is the "previous block" for the very first block.
> Different IV + same key = completely different ciphertext.

> **Critical detail — key derivation (easy to get wrong):**
> The binary does NOT hash the full key. It hashes each half separately:
> - `aes_key = SHA256(key[:16])` — first 16 characters
> - `iv      = MD5(key[16:])`   — last 16 characters
>
> Confirmed via dynamic analysis in pwndbg by breaking on `crypto/sha256.Sum256`
> and `crypto/md5.Sum` and inspecting the `RAX` register (Go passes slice pointer there).

**Verification:**
```python
import hashlib
from Crypto.Cipher import AES

key     = b"Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!"
enc     = bytes.fromhex("0037a8858c84fd73233ee93571d82bde4f1846e81241af6df95ed4bd156a8999")

aes_key = hashlib.sha256(key[:16]).digest()
iv      = hashlib.md5(key[16:]).digest()
pt      = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc)

print(pt)   # b'crackme{AES_gh0stk3y_r3v3rs3d!!}'
```

---

## Phase 2 — Solve Strategy

### Why Z3?

| Approach | Why it fails |
|---|---|
| GDB breakpoint on strcmp | No strcmp — AES key derived from input |
| Brute force | 95^32 ≈ 10^62 combinations — impossible |
| Manual reversal | 9 interdependent checks on same 32 bytes |
| **Z3 SMT Solver** | **All checks expressible as constraints — correct choice** |

Z3 is a mathematical solver (like a sudoku solver). You give it rules, it finds values that satisfy all rules simultaneously.

### The Critical Z3 Insight: Theory Mixing

Z3 has multiple reasoning engines:
```
Bitvector engine:   handles >>, <<, XOR, AND, OR    (bit manipulation)
Arithmetic engine:  handles +, -, %, URem            (math)
Array engine:       handles table lookups            (S-Box)
```

When you force Z3 to use multiple engines at once (e.g., LFSR bitvector + pair URem), the engines must coordinate via DPLL(T) protocol — which can be extremely slow or fail entirely.

**Solution:** Express LFSR branch-free (stays in bitvector engine). Leave S-Box out of Z3 (filter in Python). Result: Z3 finds solutions fast; Python filters the ~5 candidates needed.

---

## Phase 3 — The Solver

```python
#!/usr/bin/env python3
# solver.py — ghostkey challenge solver
# Strategy: Z3 for all constraints except S-Box (filtered in Python)
# LFSR encoded with branch-free bitmask trick (key performance insight)

from z3 import *
import hashlib
from Crypto.Cipher import AES

# ── All extracted data ────────────────────────────────────────────────────────

TARGET_LFSR   = 0x4358
INIT_LFSR     = 0xACE1
POLY          = 0xB400

TARGET_NIBBLE = [0x08, 0x08, 0x04, 0x07]
TARGET_COL    = [12, 39, 8, 0, 55, 33, 50, 96]
TARGET_TAG    = [108, 117, 58, 1, 126, 47, 52, 0]

PAIRS = [
    (0,  31, 0x7F, 0x68),
    (3,  28, 0x83, 0x11),
    (7,  24, 0x71, 0x35),
    (11, 20, 0x6D, 0x3A),
    (1,  15, 0x67, 0x34),
    (5,  27, 0x61, 0x58),
    (9,  22, 0x6B, 0x14),
    (13, 18, 0x65, 0x40),
    (2,  29, 0x7F, 0x51),
    (6,  25, 0x83, 0x76),
    (10, 21, 0x71, 0x28),
    (14, 17, 0x6D, 0x53),
]

ENC = bytes.fromhex(
    "0037a8858c84fd73233ee93571d82bde"
    "4f1846e81241af6df95ed4bd156a8999"
)

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

# ── Python-side verifiers ─────────────────────────────────────────────────────

def sbox_check(key: bytes) -> bool:
    acc = 0
    for i in range(0, 32, 2):
        acc ^= SBOX[key[i]]
    return acc == 0x66

def aes_decrypt(key: bytes):
    aes_key = hashlib.sha256(key[:16]).digest()   # SHA256 of FIRST half
    iv      = hashlib.md5(key[16:]).digest()       # MD5 of LAST half
    return AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ENC)

# ── Z3 solver setup ───────────────────────────────────────────────────────────

s = Solver()
s.set(timeout=0)   # no timeout — let Z3 run as long as needed

k = [BitVec(f'k{i}', 8) for i in range(32)]

# Check 2: Printable ASCII [0x20, 0x7E]
for x in k:
    s.add(UGE(x, 0x20), ULE(x, 0x7E))

# Check 8: Tag XOR — every 4 bytes XOR to target
for i in range(8):
    a = 4 * i
    s.add(k[a] ^ k[a+1] ^ k[a+2] ^ k[a+3] == BitVecVal(TARGET_TAG[i], 8))

# Check 4: Nibble XOR — 4 groups of 8 bytes
for g in range(4):
    acc = BitVecVal(0, 8)
    for j in range(8):
        v   = k[8*g + j]
        acc = acc ^ (LShR(v, 4) ^ (v & BitVecVal(0x0F, 8)))
    s.add(acc == BitVecVal(TARGET_NIBBLE[g], 8))

# Check 5: Column sums mod 97
for col in range(8):
    col_sum = (ZeroExt(8, k[col]) + ZeroExt(8, k[col+8]) +
               ZeroExt(8, k[col+16]) + ZeroExt(8, k[col+24]))
    s.add(URem(col_sum, BitVecVal(97, 16)) == BitVecVal(TARGET_COL[col], 16))

# Check 6: Pair modular constraints
for a, b, mod, rem in PAIRS:
    pair_sum = ZeroExt(8, k[a]) + ZeroExt(8, k[b])
    s.add(URem(pair_sum, BitVecVal(mod, 16)) == BitVecVal(rem, 16))

# Check 3: LFSR — branch-free bitmask encoding (THE KEY TRICK)
# Why: If() creates 2^256 decision branches → Z3 times out
# Fix: arithmetic mask — -0=0x0000, -1=0xFFFF → no branch needed
state = BitVecVal(INIT_LFSR, 16)
poly  = BitVecVal(POLY, 16)

for i in range(32):
    for bit in range(8):
        # Extract bit 'bit' from k[i], zero-extend to 16 bits
        u     = ZeroExt(15, Extract(bit, bit, k[i]))
        # XOR lowest bit of (state ^ byte_bit)
        lsb   = (state ^ u) & BitVecVal(1, 16)
        # mask = 0xFFFF if lsb=1, 0x0000 if lsb=0  (two's complement trick)
        mask  = -lsb
        # Conditional XOR via multiplication: no If() needed
        state = LShR(state, 1) ^ (poly & mask)

s.add(state == BitVecVal(TARGET_LFSR, 16))

# ── Enumerate solutions, filter S-Box in Python ───────────────────────────────

print("[*] Solving... (Z3 includes LFSR, S-Box filtered in Python)")

found = 0
attempt = 0

while True:
    result = s.check()
    if result != sat:
        print(f"[*] Z3 exhausted after {attempt} attempts: {result}")
        break

    m   = s.model()
    key = bytes([m.evaluate(k[i], model_completion=True).as_long() for i in range(32)])
    attempt += 1

    ok = sbox_check(key)
    print(f"  #{attempt} sbox={'✓' if ok else '✗'} → {key.decode('ascii', errors='replace')}")

    if ok:
        # AES final verification
        pt = aes_decrypt(key)
        if pt.startswith(b"crackme{"):
            print(f"\n[+] KEY:  {key.decode()}")
            print(f"[+] FLAG: {pt.decode()}")
            found += 1
            break
        else:
            print(f"  [!] S-Box passed but AES failed — check key derivation")

    # Block this solution and find the next
    s.add(Or([k[i] != m.evaluate(k[i], model_completion=True) for i in range(32)]))

if not found:
    print("[-] No solution found")
```

### Running the Solver

```bash
pip install z3-solver pycryptodome

python3 solver.py
```

Expected output:
```
[*] Solving... (Z3 includes LFSR, S-Box filtered in Python)
  #1 sbox=✗ → yn'\#%G4k0.OF)C-:}|EXkOSr/Z38*|n
  #2 sbox=✗ → o{.VqN4~ByGFJ K Vu }aRqm(B5k>#ex
  #3 sbox=✗ → *4"P0jAnl4%G%7tgaLn=`tKp85vOD/U>
  #4 sbox=✗ → *h_qS8~`%@h7tj,39';[p1?QF{) #ql>
  #5 sbox=✓ → Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!

[+] KEY:  Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!
[+] FLAG: crackme{AES_gh0stk3y_r3v3rs3d!!}
```

Z3 needs only **5 attempts** because the LFSR constraint strongly limits the valid search space. Without LFSR in Z3, thousands of fake solutions appear.

---

## Phase 4 — Getting the Flag

After finding the key, the AES decryption gives us the flag:

```python
import hashlib
from Crypto.Cipher import AES

key = b"Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!"
enc = bytes.fromhex("0037a8858c84fd73233ee93571d82bde4f1846e81241af6df95ed4bd156a8999")

# Key derivation — CONFIRMED by dynamic analysis in pwndbg:
# SHA256 operates on key[:16], MD5 operates on key[16:]
aes_key = hashlib.sha256(key[:16]).digest()
iv      = hashlib.md5(key[16:]).digest()

pt = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc)
print(pt.decode())
# crackme{AES_gh0stk3y_r3v3rs3d!!}
```

Binary confirmation:
```bash
./ghost "Gh0stK3y-R3v3rs3-M3-1f-U-C4n!!!!"
# [+] All checks passed!
# [+] Flag: crackme{AES_gh0stk3y_r3v3rs3d!!}
```

**FLAG: `crackme{AES_gh0stk3y_r3v3rs3d!!}`**

---

## Key Lessons and Mistakes

### Mistake 1: Wrong AES Key Derivation (Static vs Dynamic)

I initially assumed both SHA256 and MD5 operated on the **full** 32-byte key:
```python
# WRONG:
aes_key = hashlib.sha256(key).digest()     # whole key
iv      = hashlib.md5(key).digest()        # whole key
```

The binary actually hashes each **half** separately:
```python
# CORRECT (confirmed by pwndbg):
aes_key = hashlib.sha256(key[:16]).digest()   # first 16 bytes
iv      = hashlib.md5(key[16:]).digest()       # last 16 bytes
```

**Lesson:** Never trust static reading of decompiled Go code for slice boundaries.
Always verify with dynamic analysis — set a breakpoint on the hash function and
inspect the exact bytes passed in registers.

```bash
# pwndbg commands to verify:
pwndbg> b crypto/sha256.Sum256
pwndbg> run "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
pwndbg> c
pwndbg> x/16c $rax     # shows exactly which 16 bytes were passed
```

---

### Mistake 2: Wrong LFSR Encoding in Z3

Using `If()` for conditional XOR in the LFSR:
```python
# WRONG — creates 2^256 branches, Z3 times out:
st = If(lsb != 0, st ^ BitVecVal(0xB400, 16), st)
```

The fix — arithmetic bitmask:
```python
# CORRECT — no branches, pure arithmetic:
mask  = -lsb   # two's complement: -0=0x0000, -1=0xFFFF
state = LShR(state, 1) ^ (poly & mask)
```

**Lesson:** When encoding conditional logic in Z3 bitvector formulas, always look
for an arithmetic equivalent. `If()` creates decision branches that multiply exponentially.
The `-lsb` mask trick converts conditional XOR into unconditional arithmetic — same result,
Z3 solves it as algebra instead of tree search.

---

### Mistake 3: Diagnosing Symptom Not Cause

When Z3 returned `unknown` (timeout), I removed constraints thinking the problem was
"too many constraints." The real cause was the wrong encoding of one constraint.

```
Wrong diagnosis: "Too many constraints → remove some"
Right diagnosis: "LFSR uses If() → fix encoding → keep all constraints"
```

**Lesson:** Z3 returning `unknown` almost always means:
1. An `If()` node inside bitvector arithmetic (use mask trick)
2. Two incompatible theories mixed together (separate and filter in Python)
3. Expression too large (simplify the encoding)

It almost never means "remove constraints." Fix the encoding first.

---

### Mistake 4: Not Benchmarking Alternative Encodings

I benchmarked which constraints were slow, but never asked "is there a faster way
to express the same constraint?" The benchmark should include:

```python
# Benchmark If() version:
t0 = time.time(); s.check(); print(f"If() version: {time.time()-t0:.2f}s")

# Benchmark mask version:
t0 = time.time(); s.check(); print(f"Mask version: {time.time()-t0:.2f}s")
```

**Lesson:** When a constraint is slow, try rewriting it before removing it.

---

### General Lessons for Future Challenges

| Situation | Action |
|---|---|
| Binary not stripped | Read symbol names first — they tell you everything |
| Go binary static analysis | Trust dynamic analysis over Ghidra decompilation for slice details |
| Z3 returns `unknown` | Fix the encoding (use mask trick for conditionals) — don't remove constraints |
| Z3 returns many fake solutions | Key constraint is missing or wrongly encoded |
| Mixed modular + bitwise constraints | Separate them — let Z3 handle each theory cleanly |
| S-Box lookup in Z3 | Use Z3 Array theory, or filter in Python |
| AES key derivation | Always verify dynamically — static reading is error-prone |
| Too many Z3 solutions before finding real one | A strong constraint (like LFSR) is missing from Z3 |

---

### The LFSR Mask Trick — Reference

```python
# For any LFSR step that does:
#   if condition: state ^= POLY
#   else:         state stays the same

# SLOW (creates branches):
state = If(condition, state ^ POLY, state)

# FAST (pure arithmetic):
bit  = condition & 1              # ensure it's 0 or 1
mask = -bit                       # 0→0x0000, 1→0xFFFF (two's complement)
state = state ^ (POLY & mask)    # POLY if condition=1, 0 if condition=0
```

This pattern appears in CRC computations, LFSR implementations, and any
conditional-XOR operation. Memorize it for future Z3 challenges.

---

*Challenge solved. Flag: `crackme{AES_gh0stk3y_r3v3rs3d!!}`*
                                                                        
