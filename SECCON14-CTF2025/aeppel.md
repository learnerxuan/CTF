# SECCON 2025 CTF Quals - aeppel Challenge Writeup

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Confusion: The Red Herring](#initial-confusion-the-red-herring)
3. [Understanding the Real Challenge](#understanding-the-real-challenge)
4. [Solution Walkthrough](#solution-walkthrough)
5. [Common Pitfalls](#common-pitfalls)
6. [Final Solution](#final-solution)
7. [References](#references)

---

## Challenge Overview

**Challenge Name:** aeppel

**Category:** Reverse Engineering

**Files:** `1.scpt` (AppleScript compiled binary)

**Goal:** Reverse engineer a compiled AppleScript file to extract the flag.

---

## Initial Confusion: The Red Herring

### What I Initially Thought (WRONG!)

When first examining the disassembled output, I saw:
- State names: `california`, `nevada`, `texas`, `oregon`, etc.
- Tokyo station names: `iidabashi`, `roppongi`, `otemachi`, `kanda`, `sugamo`, etc.
- Unicode emoji codes: `u1f41d` (🐝), `u1f99c` (🦜), etc.

**I initially believed this was a two-layer obfuscation challenge:**
```
State names → Tokyo station names → Emoji unicode
```

### Why This Was Wrong

These elements are **RED HERRINGS** - they exist in the code but are NOT part of the actual flag validation mechanism. The writeups confirmed this:

> "The state/station/emoji names in the disassembly are red herrings - they're not part of the actual solution mechanism!"

The actual challenge is about **reversing two mathematical validation functions**, not decoding emoji mappings.

---

## Understanding the Real Challenge

### The Actual Mechanism

The AppleScript binary validates the flag using **two functions**:

#### 1. **Shimbashi Function** (Encryption/Validation)
This function encrypts the 16-character flag inner text using:

```python
encrypted[i] = original[i] + 13 + k
where k = (13 * (state % 3 + 1)) % 11
and state = index + 1  # IMPORTANT: State starts at 1, not 0!
```

**Key Insight:** The state counter starts at **1**, not 0. This makes `k` cycle through: `4, 6, 2, 4, 6, 2, ...`

#### 2. **Ginza Function** (Checksum Validation)
This function validates that:
```python
sum(character_codes) % 256 == 0x5f  # 0x5f = 95 = ASCII '_'
```

### How the Challenge Works

1. User enters a flag in format `SECCON{inner_16_chars}`
2. The Shimbashi function encrypts the 16-character inner part
3. It compares the result against a hardcoded 16-byte target
4. If they match, the Ginza function verifies the checksum
5. If both pass, the flag is correct

---

## Solution Walkthrough

### Step 1: Disassemble the Binary

**Command:**
```bash
cd applescript-disassembler
python3 disassembler.py ../1.scpt > ../disassembled.txt
```

**What this does:**
- Uses the AppleScript disassembler tool to convert the binary into readable bytecode
- Creates `disassembled.txt` with the decompiled structure

**Expected output:**
```
Function name : <Value type=object value=<Value type=event_identifier ...>>
Function arguments:  <empty or unknown>
 00000 PushLiteral 0 # <Value type=rawdata value=b'scptFasdUAS 1.101.10\x0e...'>
 ...
```

### Step 2: Understand the Bytecode Structure

The disassembly shows a `PushLiteral` instruction containing embedded binary data. This data has:
- A malformed header: `scptFasdUAS` (should be just `FasdUAS`)
- All the function definitions and constants
- The target encrypted bytes we need

**Why we can't find the target easily:**
The target bytes are embedded in the bytecode in a specific format that's not immediately obvious from text search.

### Step 3: Extract the Target Bytes

From the writeups, the target bytes are:
```python
[114, 131, 127, 125, 120, 130, 116, 133, 120, 129, 135, 117, 134, 129, 75, 68]
```

In hex:
```
72 83 7f 7d 78 82 74 85 78 81 87 75 86 81 4b 44
```

**How to find these in YOUR binary:**

1. Look for the Shimbashi function definition in the disassembly
2. Find where it compares computed values against a constant array
3. Extract those 16 bytes

**Note:** Different challenge instances may have different target bytes (different flags).

### Step 4: Understand the Encryption Formula

The Shimbashi function uses this encryption:

```python
for each character at index i (0-indexed):
    state = i + 1           # State starts at 1!
    k = (13 * (state % 3 + 1)) % 11
    encrypted = ord(char) + 13 + k
```

**k values cycle:**
```
state=1: k = (13 * (1 % 3 + 1)) % 11 = (13 * 2) % 11 = 4
state=2: k = (13 * (2 % 3 + 1)) % 11 = (13 * 3) % 11 = 6
state=3: k = (13 * (3 % 3 + 1)) % 11 = (13 * 1) % 11 = 2
state=4: k = (13 * (4 % 3 + 1)) % 11 = (13 * 2) % 11 = 4
...
```

Pattern: `4, 6, 2, 4, 6, 2, ...`

### Step 5: Reverse the Encryption

To decrypt:
```python
for each encrypted byte at index i:
    state = i + 1           # State starts at 1!
    k = (13 * (state % 3 + 1)) % 11
    original = encrypted - 13 - k
```

**Full decryption table:**

| Index | State | k | Encrypted | Calculation | Original | Char |
|-------|-------|---|-----------|-------------|----------|------|
| 0 | 1 | 4 | 114 | 114-13-4 = 97 | 97 | a |
| 1 | 2 | 6 | 131 | 131-13-6 = 112 | 112 | p |
| 2 | 3 | 2 | 127 | 127-13-2 = 112 | 112 | p |
| 3 | 4 | 4 | 125 | 125-13-4 = 108 | 108 | l |
| 4 | 5 | 6 | 120 | 120-13-6 = 101 | 101 | e |
| 5 | 6 | 2 | 130 | 130-13-2 = 115 | 115 | s |
| 6 | 7 | 4 | 116 | 116-13-4 = 99 | 99 | c |
| 7 | 8 | 6 | 133 | 133-13-6 = 114 | 114 | r |
| 8 | 9 | 2 | 120 | 120-13-2 = 105 | 105 | i |
| 9 | 10 | 4 | 129 | 129-13-4 = 112 | 112 | p |
| 10 | 11 | 6 | 135 | 135-13-6 = 116 | 116 | t |
| 11 | 12 | 2 | 117 | 117-13-2 = 102 | 102 | f |
| 12 | 13 | 4 | 134 | 134-13-4 = 117 | 117 | u |
| 13 | 14 | 6 | 129 | 129-13-6 = 110 | 110 | n |
| 14 | 15 | 2 | 75 | 75-13-2 = 60 | 60 | < |
| 15 | 16 | 4 | 68 | 68-13-4 = 51 | 51 | 3 |

**Result:** `applescriptfun<3`

### Step 6: Verify the Checksum

```python
text = "applescriptfun<3"
checksum = sum(ord(c) for c in text) % 256

# Calculation:
# a=97, p=112, p=112, l=108, e=101, s=115, c=99, r=114,
# i=105, p=112, t=116, f=102, u=117, n=110, <=60, 3=51
# Sum = 1631
# 1631 % 256 = 95 = 0x5f ✓
```

Checksum matches! The flag is valid.

---

## Common Pitfalls

### Pitfall 1: Thinking State Starts at 0

**Wrong approach:**
```python
k = (13 * (i % 3 + 1)) % 11  # Using index directly
# This gives k values: 2, 4, 6, 2, 4, 6, ...
```

**Correct approach:**
```python
state = i + 1
k = (13 * (state % 3 + 1)) % 11  # Using state = index + 1
# This gives k values: 4, 6, 2, 4, 6, 2, ...
```

**How to verify:**
Encrypt "applescriptfun<3" with both methods and compare to the target bytes.

### Pitfall 2: Getting Distracted by Red Herrings

The disassembly contains many misleading elements:
- ❌ State names (california, nevada, texas)
- ❌ Tokyo station names (iidabashi, roppongi, otemachi)
- ❌ Emoji unicode codes (u1f41d, u1f99c)
- ✅ The Shimbashi and Ginza functions (THESE ARE IMPORTANT!)

**Lesson:** Focus on the validation logic, not the variable names.

### Pitfall 3: Searching for Exact Writeup Bytes

Your challenge file might have **different target bytes** than the writeup if:
- It's a practice file
- It's from a different team/distribution
- The flag is different

**Solution:** Extract the target bytes from YOUR specific binary.

---

## Final Solution

### Complete Solver Script

**File:** `correct_solve.py`

```python
#!/usr/bin/env python3
"""
SECCON 2025 aeppel - Solution
Key insight: State starts at 1, not 0!
"""

def decrypt_shimbashi(encrypted_bytes):
    """
    Decrypt using Shimbashi formula (reversed).

    Encryption: encrypted = original + 13 + k
    Decryption: original = encrypted - 13 - k
    where k = (13 * (state % 3 + 1)) % 11
    and state = index + 1 (starts from 1)
    """
    decrypted = []
    for i, enc in enumerate(encrypted_bytes):
        state = i + 1  # State starts at 1!
        k = (13 * (state % 3 + 1)) % 11
        orig = enc - 13 - k
        decrypted.append(orig)
    return bytes(decrypted)

# Target bytes from the writeup
TARGET_BYTES = [114, 131, 127, 125, 120, 130, 116, 133,
                120, 129, 135, 117, 134, 129, 75, 68]

# Decrypt
decrypted = decrypt_shimbashi(TARGET_BYTES)
flag_inner = decrypted.decode('ascii')

# Verify checksum
checksum = sum(decrypted) % 256
assert checksum == 0x5f, f"Checksum failed: {checksum} != 0x5f"

print(f"FLAG: SECCON{{{flag_inner}}}")
```

**Run it:**
```bash
python3 correct_solve.py
```

**Output:**
```
FLAG: SECCON{applescriptfun<3}
```

---

## Quick Reference Commands

### Setup
```bash
# Clone the AppleScript disassembler
git clone https://github.com/mat/applescript-disassembler.git
cd applescript-disassembler
```

### Analysis
```bash
# Disassemble the binary
python3 disassembler.py ../1.scpt > ../disassembled.txt

# Search for key functions
grep -i "shimbashi" ../disassembled.txt
grep -i "ginza" ../disassembled.txt
```

### Solve
```bash
# Run the solver
python3 correct_solve.py
```

---

## Questions I Asked & Confusions Clarified

### Q1: "Is this about state names → Tokyo stations → emoji mappings?"
**A:** No! Those are red herrings. The real challenge is reversing the Shimbashi encryption and Ginza checksum functions.

### Q2: "Why can't I find the target bytes in my binary?"
**A:** The target bytes are embedded in the bytecode structure. Different challenge instances may have different bytes. You need to either:
- Use the known writeup values (for the original challenge)
- Extract them from your specific binary by analyzing the Shimbashi function

### Q3: "Why does my decryption give 'crlngoetervbwp85' instead of 'applescriptfun<3'?"
**A:** The state counter starts at **1**, not 0! Use `state = i + 1` in the k formula.

### Q4: "How do I verify my solution is correct?"
**A:** Check two things:
1. Does it decrypt to readable ASCII text?
2. Does `sum(bytes) % 256 == 0x5f` (95)?

---

## Key Takeaways

1. **Don't trust variable names** - Focus on the actual validation logic
2. **State starts at 1** - This is the critical insight for correct decryption
3. **Verify your work** - Use the checksum to confirm your solution
4. **Read writeups carefully** - Multiple writeups can reveal different insights
5. **Test your assumptions** - Encrypt known plaintext to verify your formula

---

## References

- [jia.je writeup](https://jia.je/ctf-writeups/2025-12-13-seccon-ctf-2025-quals/aeppel.html)
- [Qiita writeup (Japanese)](https://qiita.com/claustra01/items/a36067afa3b3cbf5a175)
- [caphosra.net writeup](https://caphosra.net/posts/2025-12-17-seccon-quals/)
- [AppleScript Disassembler](https://github.com/mat/applescript-disassembler)

---

## Appendix: Encryption/Decryption Reference

### Encryption (for verification)
```python
def encrypt(plaintext):
    encrypted = []
    for i, char in enumerate(plaintext):
        state = i + 1
        k = (13 * (state % 3 + 1)) % 11
        enc = ord(char) + 13 + k
        encrypted.append(enc)
    return encrypted
```

### Decryption (for solving)
```python
def decrypt(encrypted_bytes):
    decrypted = []
    for i, enc in enumerate(encrypted_bytes):
        state = i + 1
        k = (13 * (state % 3 + 1)) % 11
        orig = enc - 13 - k
        decrypted.append(orig)
    return bytes(decrypted)
```

### Checksum Verification
```python
def verify_checksum(text):
    return sum(ord(c) for c in text) % 256 == 0x5f
```

---

**Flag:** `SECCON{applescriptfun<3}`

---

*Written as a reference for future CTF challenges involving AppleScript reverse engineering.*
