# osuCTF 2025 - bleh Challenge Writeup

**Category:** Reverse Engineering   
**Difficulty:** 2/5  
**Authors:** sahuang, es3n1n

---

## Challenge Description

> bleh :p  
> Charset: `[a-f0-9]+`. Concatenate all inputs, then decode as hex.

**Files provided:** 3,842 binary executables (`bleh0` through `bleh3841`)

---

## Table of Contents

1. [Initial Analysis](#initial-analysis)
2. [Understanding the Binary](#understanding-the-binary)
3. [The Hash Function](#the-hash-function)
4. [Finding the Key String](#finding-the-key-string)
5. [Mathematical Inversion](#mathematical-inversion)
6. [Extracting Expected Hashes](#extracting-expected-hashes)
7. [Complete Solution](#complete-solution)
8. [Common Pitfalls](#common-pitfalls)
9. [Flag](#flag)

---

## Initial Analysis

### Examining the Files

```bash
$ ls dist/ | wc -l
3842

$ file dist/bleh0
dist/bleh0: ELF 64-bit LSB pie executable, x86-64, dynamically linked

$ checksec dist/bleh0
RELRO           STACK CANARY      NX            PIE
Full RELRO      Canary found      NX enabled    PIE enabled
```

### Running a Binary

```bash
$ echo "test" | ./dist/bleh0
Playing ctfs is better than osu

$ echo "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | ./dist/bleh0
Playing ctfs is better than osu
```

The binary reads input, performs some check, and prints either success or failure message. Simple inputs don't work.

---

## Understanding the Binary

### Ghidra Decompilation

Opening `bleh0` in Ghidra reveals the main function:

```c
undefined8 FUN_0010154f(void)
{
  byte bVar1;
  int iVar2;
  uint local_a0;
  int local_9c;
  
  // The KEY STRING stored as hex values
  local_98 = 0x5f474e4959344c50;  // "PL4YING_"
  local_90 = 0x4e53495f53465443;  // "CTFS_ISN"
  local_88 = 0x5f52455454454254;  // "TBETTER_"
  local_80 = 0x55534f5f4e414854;  // "THAN_OSU"
  
  // The EXPECTED HASH stored as hex values
  local_38 = 0x5521f3ca562317a0;
  local_30 = 0x26b446d472370ace;
  local_28 = 0x37019623b7840c91;
  local_20 = 0xc38a1cf4c19819a5;
  
  char local_78[32];  // User input
  byte local_58[32];  // Computed hash
  
  // Read 32 bytes from stdin
  read(0, local_78, 0x20);
  
  // Hash the input
  local_a0 = 0x1337;  // Initial state
  for (local_9c = 0; local_9c < 0x20; local_9c++) {
    bVar1 = FUN_00101337(
      local_78[local_9c],   // Input byte
      local_98[local_9c],   // Key byte
      local_a0              // Current state
    );
    local_a0 = bVar1;       // State updates
    local_58[local_9c] = bVar1;
  }
  
  // Compare computed hash vs expected hash
  iVar2 = strncmp(local_58, local_38, 0x20);
  
  if (iVar2 == 0) {
    puts("Nicely done");
  } else {
    puts("Playing ctfs is better than osu");
  }
  
  return 0;
}
```

### Key Observations

1. **32-byte input:** The binary expects exactly 32 bytes
2. **Stateful hash:** Each byte is hashed with a state that carries forward
3. **Key string:** A 32-byte key is used in hashing
4. **Expected hash:** Each binary has a different expected hash value
5. **Success condition:** Computed hash must match expected hash

---

## The Hash Function

### Analyzing FUN_00101337

The hash function at offset `0x1337` performs these operations:

```c
byte FUN_00101337(int input_byte, int key_byte, int state) {
    // Step 1: Add 6 to input
    input_byte = input_byte + 6;
    
    // Step 2: Add 128 to key
    key_byte = key_byte + 0x80;
    
    // Step 3: Subtract 128 from state
    state = state - 0x80;
    
    // Step 4: XOR and add
    int temp = input_byte ^ key_byte;
    int result = temp + state;
    
    // Step 5: Keep only 1 byte
    return result & 0xFF;
}
```

### Hash Algorithm Summary

```
For each byte position i (0 to 31):
    1. Modify input: input[i] + 6
    2. Modify key: key[i] + 128
    3. Modify state: state - 128
    4. XOR: (input+6) ^ (key+128)
    5. Add: XOR_result + (state-128)
    6. Update state: state = hash[i]
```

**Initial state:** `0x1337`

---

## Finding the Key String

### Converting Hex to ASCII

The key is stored as four 64-bit values (little-endian):

```python
import struct

key_parts = [
    0x5f474e4959344c50,  # First 8 bytes
    0x4e53495f53465443,  # Next 8 bytes
    0x5f52455454454254,  # Next 8 bytes
    0x55534f5f4e414854   # Last 8 bytes
]

key = b''
for part in key_parts:
    key += struct.pack('<Q', part)  # Little-endian format

print(key)
# Output: b'PL4YING_CTFS_ISNTBETTER_THAN_OSU'
```

### Breaking Down the Hex

```
0x5f474e4959344c50 (little-endian):
  50 4c 34 59 49 4e 47 5f
  P  L  4  Y  I  N  G  _

0x4e53495f53465443:
  43 54 46 53 5f 49 53 4e
  C  T  F  S  _  I  S  N

0x5f52455454454254:
  54 42 45 54 54 45 52 5f
  T  B  E  T  T  E  R  _

0x55534f5f4e414854:
  54 48 41 4e 5f 4f 53 55
  T  H  A  N  _  O  S  U
```

**Important Note:** The key is `ISNTBETTER`, not `IS_BETTER`! This is different from what appears in the strings output.

---

## Mathematical Inversion

### Why Inversion is Possible

The hash function only uses **reversible operations**:
- Addition/Subtraction (inverse of each other)
- XOR (self-inverse: `A ^ B ^ B = A`)
- AND with 0xFF (keeps values in byte range)

No information is lost during hashing, so we can work backwards!

### Deriving the Inversion Formula

**Forward hash:**
```
hash = ((input + 6) ^ (key + 128)) + (state - 128)
```

**Solving for input:**
```
Step 1: Subtract (state - 128)
    (input + 6) ^ (key + 128) = hash - (state - 128)

Step 2: XOR with (key + 128) to undo XOR
    input + 6 = [hash - (state - 128)] ^ (key + 128)

Step 3: Subtract 6
    input = {[hash - (state - 128)] ^ (key + 128)} - 6
```

### Implementation

```python
def invert(hash_byte, prev_hash_byte, key_byte):
    """
    Invert one byte of the hash function
    
    Args:
        hash_byte: Current hash byte (result we want to reverse)
        prev_hash_byte: Previous hash byte (becomes state)
        key_byte: Corresponding key byte
    
    Returns:
        Original input byte
    """
    # Compute the state for this position
    state = (prev_hash_byte - 0x80) & 0xFF
    
    # Compute modified key
    k = (key_byte + 0x80) & 0xFF
    
    # Reverse: subtract state
    temp = (hash_byte - state) & 0xFF
    
    # Reverse: XOR with modified key
    input_plus_6 = temp ^ k
    
    # Reverse: subtract 6
    input_byte = (input_plus_6 - 6) & 0xFF
    
    return input_byte
```

### Example: Inverting First Byte of bleh0

```python
# Given values
hash_byte = 0x73        # First byte of expected hash
prev_hash = 0x1337      # Initial state
key_byte = ord('P')     # First key byte (0x50)

# Step by step
state = (0x1337 - 0x80) & 0xFF  # = 0xB7 = 183
k = (0x50 + 0x80) & 0xFF        # = 0xD0 = 208
temp = (0x73 - 183) & 0xFF      # = 0xBC = 188
input_plus_6 = 188 ^ 208        # = 0x6C = 108
input_byte = (108 - 6) & 0xFF   # = 0x66 = 102

# Result
print(chr(input_byte))  # Output: 'f'
```

The first input byte is `'f'`! ✓

---

## Extracting Expected Hashes

### Finding Hash Location

Using `xxd` to examine the binary:

```bash
$ xxd dist/bleh0 | grep "15b"
000015b0: 4889 4580 4889 5588 48b8 7393 f158 7d9f  H.E.H.U.H.s..X}.
000015c0: cb34 48ba a90b 7ce1 4674 dd4f 4889 45d0  .4H...|.Ft.OH.E.
000015d0: 4889 55d8 48b8 bd3a b921 83f6 5ac2 48ba  H.U.H..:.!..Z.H.
```

The hash is stored in `movabs` instructions:
- `48 b8` = `movabs rax, imm64` (loads 8-byte immediate into RAX)
- `48 ba` = `movabs rdx, imm64` (loads 8-byte immediate into RDX)

**Pattern:** `48 b8 [8 bytes of data]`

### Extraction Code

```python
def extract_hash(filename):
    """Extract 32-byte expected hash from binary"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    # Offsets where movabs instructions start
    offsets = [0x15b8, 0x15c2, 0x15d4, 0x15de]
    movsz = 2  # Skip the instruction opcode bytes (48 b8 or 48 ba)
    
    hash_bytes = b''
    for offset in offsets:
        # Read 8 bytes after the movabs instruction
        hash_bytes += data[offset + movsz:offset + movsz + 8]
    
    return hash_bytes
```

### Verification

```bash
$ python3 << 'EOF'
with open('dist/bleh0', 'rb') as f:
    data = f.read()

offsets = [0x15b8, 0x15c2, 0x15d4, 0x15de]
movsz = 2

hash_bytes = b''
for offset in offsets:
    hash_bytes += data[offset + movsz:offset + movsz + 8]

print(hash_bytes.hex())
EOF

# Output: 7393f1587d9fcb34a90b7ce14674dd4fbd3ab92183f65ac224a31a93fc75e447
```

This matches what we see with `ltrace`! ✓

---

## Complete Solution

### Understanding the Output Format

When we invert `bleh0`, we get:

```python
solution = b'ffd8ffe000104a464946000101010060'
```

**Important realization:** These are ASCII characters representing hex digits!

```python
# Each byte is an ASCII code
102 = 'f'
102 = 'f'
100 = 'd'
56  = '8'
...

# Converting to string
hex_string = ''.join([chr(b) for b in solution])
# Result: "ffd8ffe000104a464946000101010060"
```

### Recognizing the JPEG Header

Looking at the hex string: `ffd8ffe0`

This is the **JPEG file signature**! Every JPEG/JFIF file starts with:
- `FF D8` = Start of Image (SOI)
- `FF E0` = JFIF marker

The following bytes `4a 46 49 46` decode to "JFIF", confirming it's a JPEG image.

### The Complete Solution

Each binary contributes **32 hex characters**. When we concatenate all 3,842 solutions and decode from hex, we get a JPEG image containing the flag!

```python
#!/usr/bin/env python3

KEY = b"PL4YING_CTFS_ISNTBETTER_THAN_OSU"
LEN = 32

def invert(m, m_1, k):
    """Invert one byte of the hash"""
    k = (k + 0x80) & 0xFF
    return ((m - (m_1 - 0x80)) ^ k) - 6

def extract_hash(filename):
    """Extract expected hash from binary"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    offsets = [0x15b8, 0x15c2, 0x15d4, 0x15de]
    movsz = 2
    
    hash_bytes = b''
    for offset in offsets:
        hash_bytes += data[offset + movsz:offset + movsz + 8]
    
    return hash_bytes

# Solve all 3,842 binaries
all_hex_chars = []

print("Solving 3,842 binaries...\n")

for binary_id in range(3842):
    # Extract expected hash
    expected_hash = extract_hash(f'dist/bleh{binary_id}')
    
    # Invert to get input
    solution = []
    for j in range(LEN):
        prev_hash = expected_hash[j-1] if j > 0 else 0x1337
        current_hash = expected_hash[j]
        key_byte = KEY[j]
        
        input_byte = invert(current_hash, prev_hash, key_byte) & 0xFF
        solution.append(input_byte)
    
    # Convert solution bytes to hex characters
    # Each byte is an ASCII code for a hex digit
    hex_chars = ''.join([chr(b) for b in solution])
    all_hex_chars.append(hex_chars)
    
    if (binary_id + 1) % 500 == 0:
        print(f"Progress: {binary_id + 1}/3,842")

# Concatenate all hex characters
full_hex_string = ''.join(all_hex_chars)

print(f"\nTotal hex characters: {len(full_hex_string)}")
# Output: 122,944 (3,842 × 32)

print(f"First 100 chars: {full_hex_string[:100]}")

# Decode hex string to binary data
image_bytes = bytes.fromhex(full_hex_string)

print(f"Image size: {len(image_bytes)} bytes")
# Output: 61,472 bytes

# Save as JPEG
with open('flag.jpg', 'wb') as f:
    f.write(image_bytes)

print("\n✅ Flag image saved as flag.jpg")
```

### Running the Solution

```bash
$ python3 solve.py
Solving 3,842 binaries...

Progress: 500/3,842
Progress: 1,000/3,842
Progress: 1,500/3,842
Progress: 2,000/3,842
Progress: 2,500/3,842
Progress: 3,000/3,842
Progress: 3,500/3,842

Total hex characters: 122944
First 100 chars: ffd8ffe000104a46494600010101006000000001000100006000060000000000ffc00011080128012803012200021101
Image size: 61472 bytes

✅ Flag image saved as flag.jpg
```

### Viewing the Flag

```bash
$ file flag.jpg
flag.jpg: JPEG image data, JFIF standard 1.01

$ open flag.jpg  # or xdg-open flag.jpg on Linux
```

The image contains the flag text!

---

## Common Pitfalls

### Pitfall 1: Wrong Key String

**Mistake:** Using `PL4YING_CTFS_IS_BETTER_THAN_OSU` (28 chars, needs padding)

**Correct:** `PL4YING_CTFS_ISNTBETTER_THAN_OSU` (32 chars exactly)

The key is `ISNTBETTER`, not `IS_BETTER`!

### Pitfall 2: Incorrect Hash Extraction

**Mistake:** Reading from wrong offset or including instruction bytes

```python
# WRONG - reads instruction bytes
hash_bytes = data[0x15b8:0x15b8+32]

# CORRECT - skips instruction opcodes
hash_bytes = data[0x15ba:0x15ba+8]  # Skip "48 b8"
```

### Pitfall 3: Only Taking First Character

**Mistake:** Assuming each binary gives only 1 hex character

```python
# WRONG
flag_char = chr(solution[0])  # Only takes first byte

# CORRECT
hex_chars = ''.join([chr(b) for b in solution])  # Takes all 32 bytes
```

Each binary contributes **32 hex characters**, not 1!

### Pitfall 4: Not Recognizing JPEG Format

**Confusion:** "Why does the hex string start with `ffd8ffe0`?"

**Answer:** This is the JPEG file header:
- `FF D8` = Start of Image marker
- `FF E0` = JFIF APP0 marker
- `4A 46 49 46` = "JFIF" in ASCII

All JPEG files start with these bytes!

### Pitfall 5: Misunderstanding the Data Format

**Confusion:** "What does `bytes.fromhex()` do with the solution?"

**Explanation:**

```python
# Step 1: Inversion gives us ASCII codes
solution = [102, 102, 100, 56, ...]  # Byte values

# Step 2: Convert to characters
hex_string = "ffd8ffe0..."  # String of hex digits

# Step 3: Decode pairs of hex digits to bytes
image_data = bytes.fromhex(hex_string)
# "ff" + "d8" → byte(255) + byte(216)
# Result: b'\xff\xd8\xff\xe0...'

# This is actual binary JPEG data!
```

**Visual example of the confusion:**

```
Inversion produces:
  bytes: [102, 102, 100, 56, 102, 102, 101, 48, ...]
  
Convert to ASCII characters:
  string: "ffd8ffe0..."
  
This string contains HEX DIGITS, not binary data yet!

bytes.fromhex() converts pairs:
  "ff" → 0xFF = 255
  "d8" → 0xD8 = 216
  "ff" → 0xFF = 255
  "e0" → 0xE0 = 224
  
Result: actual JPEG binary data!
```

---

## Solution Summary

### The Attack Strategy

1. **Static Analysis**: Understand the hash function from decompilation
2. **Mathematical Inversion**: Derive the inverse formula
3. **Hash Extraction**: Find where expected hashes are stored
4. **Automation**: Process all 3,842 binaries
5. **Decode**: Concatenate results and decode from hex to get JPEG
6. **Extract Flag**: Open image to see flag text

### Key Insights

- The hash function is **mathematically reversible**
- Each binary expects **32 ASCII hex characters** as input
- All 3,842 solutions concatenate to form a **hex string**
- The hex string decodes to a **JPEG image**
- The flag is visible text inside the image

### Difficulty Breakdown

- **Easy**: Understanding one binary's behavior
- **Medium**: Recognizing mathematical inversion
- **Medium**: Extracting hashes from 3,842 binaries
- **Easy**: Recognizing JPEG format
- **Easy**: Automation with Python

Overall difficulty: **2/5** (as stated by authors)

---

## Flag

```
osu{bl3h_bleh_bl3h_m4n_1_lov3_aut0_r3vs_e4fb25f}
```

---

## Tools Used

- **Ghidra** - Binary reverse engineering and decompilation
- **Python** - Automation and mathematical inversion
- **xxd** - Hex dump analysis
- **ltrace** - Dynamic tracing to verify hashes
- **file** - File type identification

---

## Lessons Learned

1. **Mathematical Analysis First**: Before brute forcing or using complex techniques, check if the algorithm is mathematically reversible
2. **File Signatures Matter**: Recognizing `ffd8ffe0` as JPEG saved time
3. **Read Carefully**: The key string `ISNTBETTER` vs `IS_BETTER` was crucial
4. **All Data Matters**: Each binary contributes 32 chars, not just 1
5. **Static > Dynamic**: Static analysis and math solved this faster than running 3,842 binaries

---

## Alternative Approaches

### Oracle Attack (Not Recommended)

Instead of mathematical inversion, you could:
1. Map `bleh0` into memory with execute permissions
2. Call the hash function directly as an oracle
3. Backtrack through all 16 hex possibilities at each position

This works but is slower and more complex than mathematical inversion.

### Brute Force (Infeasible)

Trying all possible 32-byte inputs:
- 16^32 possibilities per binary
- 3,842 binaries
- **Completely infeasible**

The mathematical approach is the intended solution.

---

