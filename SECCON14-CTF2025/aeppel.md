# SECCON CTF 2025 Quals - aeppel (Reversing)

**Author:** rand0m  
**Category:** Reverse Engineering  
**Difficulty:** Medium  
**Flag:** `SECCON{applescriptfun<3}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Understanding AppleScript](#understanding-applescript)
3. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4. [Phase 2: Disassembling Outer Layer](#phase-2-disassembling-outer-layer)
5. [Phase 3: Extracting Inner Script](#phase-3-extracting-inner-script)
6. [Phase 4: Disassembling Inner Script](#phase-4-disassembling-inner-script)
7. [Phase 5: Finding Target Values](#phase-5-finding-target-values)
8. [Phase 6: Identifying Validation Functions](#phase-6-identifying-validation-functions)
9. [Phase 7: Reversing Shimbashi Encryption](#phase-7-reversing-shimbashi-encryption)
10. [Phase 8: Writing the Solver](#phase-8-writing-the-solver)
11. [Key Learnings](#key-learnings)

---

## Challenge Overview

We're given a compiled AppleScript binary `1.scpt` that validates a flag. The challenge requires:
- Understanding AppleScript bytecode format
- Disassembling nested scripts
- Reversing the encryption algorithm
- Decrypting target values to recover the flag

---

## Understanding AppleScript

### What is AppleScript?
AppleScript is a scripting language by Apple for automating tasks on macOS. Files with `.scpt` extension are compiled bytecode, not source code.

### Why This Challenge is Hard
1. **Platform-specific:** Most CTF players use Linux/Windows and cannot run AppleScript natively
2. **Compiled format:** Cannot be read directly like Python or JavaScript
3. **Nested obfuscation:** Contains a script within a script
4. **Obscure tooling:** Few people know how to disassemble AppleScript

---

## Phase 1: Reconnaissance

### Understanding File Signatures (Magic Bytes)

**Magic bytes** = file signature that identifies file type, stored at the beginning of the file.

Examples:
- PNG: `89 50 4E 47` (reads as ".PNG")
- ZIP: `50 4B 03 04` ("PK")
- AppleScript: `46 61 73 64` = "Fasd" in ASCII

### Commands to Run

```bash
cd ~/seccon14CTF-2025/aeppel

# Check file type
file 1.scpt
# Output: 1.scpt: AppleScript compiled

# Extract readable strings
strings 1.scpt | head -50

# Look for patterns
strings 1.scpt | grep -E "^[a-z]+$" | head -20

# Check hex structure
hexdump -C 1.scpt | head -3
```

### What We Found

**Key patterns in strings:**
- **US States:** california, nevada, texas, florida, virginia
- **Tokyo Stations:** iidabashi, roppongi, otemachi, kanda, sugamo, jimbocho
- **Unicode emoji codes:** u1f41d (🐝), u1f99c (🦜), u1f11d
- **Keywords:** flag, FLAG, codex, claude, harrison

**This reveals a two-layer substitution cipher:**
1. States → Stations
2. Stations → Emojis

**Hex dump shows:**
```
00000000  46 61 73 64 55 41 53 20  31 2e 31 30 31 2e 31 30  |FasdUAS 1.101.10|
```
- Magic bytes: `FasdUAS` = AppleScript compiled format
- Version: 1.101.10

---

## Phase 2: Disassembling Outer Layer

### Setting Up the Disassembler

```bash
cd ~/seccon14CTF-2025/aeppel
git clone https://github.com/Jinmo/applescript-disassembler
cd applescript-disassembler
```

### Disassemble the Outer Script

```bash
python3 disassembler.py ../1.scpt > ../disassembled.txt
```

### What We See

```
=== data offset 2 ===
Function name : <Value type=object value=<Value type=event_identifier value=b'aevt'-b'oapp'-b'null'-b'\x00\x00\x80\x00'-b'****'-b'\x00\x00\x90\x00'>>
Function arguments:  <empty or unknown>
 00000 PushLiteral 0 # <Value type=rawdata value=b'scptFasdUAS 1.101.10\x0e\x00\x00\x00\x04\x0f\xff\xff...
 00001 Push0
 00002 MessageSend 1 # <Value type=object value=<Value type=event_identifier value=b'syso'-b'dsct'-b'****'-b'\x00\x00\x00\x00'-b'scpt'-b'\x00\x00\x00\x00'>>
```

### Understanding the Structure

**Key finding:** `scptFasdUAS` appears in the rawdata

This means:
```
Outer AppleScript {
    rawdata = b'scptFasdUAS...'  ← Another compiled AppleScript!
    run script rawdata
}
```

**It's AppleScript inception** - a script running a script!

### Why Do This?
**Obfuscation.** Makes analysis harder because you need to:
1. Disassemble outer layer
2. Extract the embedded data
3. Disassemble inner layer

---

## Phase 3: Extracting Inner Script

### Create Extraction Script

```bash
cd ~/seccon14CTF-2025/aeppel/applescript-disassembler
nano extract.py
```

**extract.py:**
```python
#!/usr/bin/env python3
import ast
import subprocess

# Run disassembler and capture output
p = subprocess.run(
    ["python3", "disassembler.py", "../1.scpt"],
    capture_output=True,  # Get stdout as string
    text=True,
)

s = p.stdout  # Store the disassembly output

# Find where rawdata starts
k = s.find("Value type=rawdata value=")
a = s.find("b'", k)  # Find the b' after that
q = "'"
if a == -1:
    a = s.find('b"', k)
    q = '"'

# Walk through string character by character to find the end
i = a + 2  # Skip past b'
esc = False
while True:
    c = s[i]
    if esc:
        esc = False  # Last char was \, this is escaped
    elif c == "\\":
        esc = True   # Next char is escaped
    elif c == q:     # Found closing '
        break
    i += 1

# Convert string representation to actual bytes
raw = ast.literal_eval(s[a : i + 1])
# Example: "b'scpt\\x00'" → actual bytes

# Save it
with open("raw.bin", "wb") as f:
    f.write(raw)

print(f"Extracted {len(raw)} bytes to raw.bin")
```

### How It Works

1. **Runs disassembler:** Captures output as text
2. **Finds rawdata:** Searches for the embedded AppleScript
3. **Parses carefully:** Handles escape sequences like `\x00`, `\\'`
4. **Converts to bytes:** Uses `ast.literal_eval()` to convert string representation to actual bytes
5. **Saves to file:** Writes binary data to `raw.bin`

### Run Extraction

```bash
python3 extract.py
# Output: Extracted XXXXX bytes to raw.bin
```

### Verify What We Got

```bash
hexdump -C raw.bin | head -3
```

**Output:**
```
00000000  73 63 70 74 46 61 73 64  55 41 53 20 31 2e 31 30  |scptFasdUAS 1.10|
```

**Problem:** Extra `scpt` prefix (4 bytes). Valid AppleScript should start with `Fasd`.

### Remove Extra Header

The `dd` command (disk dump) copies files with control over byte positions.

```bash
dd if=raw.bin of=inner.scpt bs=1 skip=4
```

**Parameters:**
- `if=raw.bin` - **Input File**
- `of=inner.scpt` - **Output File**  
- `bs=1` - **Block Size** = 1 byte (process byte-by-byte)
- `skip=4` - **Skip first 4 blocks** (4 bytes)

**Visual representation:**
```
raw.bin:     [s][c][p][t][F][a][s][d][U][A][S]...
              └─────────┘    └─────────────────→
              skip these 4   copy from here

inner.scpt:               [F][a][s][d][U][A][S]...
```

### Verify Success

```bash
file inner.scpt
# Should show: inner.scpt: AppleScript compiled

ls -lh inner.scpt
```

---

## Phase 4: Disassembling Inner Script

### Disassemble

```bash
cd ~/seccon14CTF-2025/aeppel/applescript-disassembler
python3 disassembler.py inner.scpt > inner_disasm.txt
```

### Check Output

```bash
wc -l inner_disasm.txt
# Should show ~1640 lines

head -50 inner_disasm.txt
```

### Find Flag-Related Code

```bash
grep -n "SECCON\|flag\|FLAG" inner_disasm.txt
# Output: 67: 00030 PopGlobal b'FLAG'
```

### Understanding the Dialog Without macOS

Look at the disassembly around line 28:

```
00000 PushLiteral 0 # [177, <Value type=string value=b'\x00E\x00n\x00t\x00e\x00r\x00 \x00t\x00h\x00e\x00 \x00f\x00l\x00a\x00g'>]
```

**Decoding `\x00E\x00n\x00t\x00e\x00r...`:**
- `\x00` = null byte (UTF-16 encoding)
- Reading every other byte: `E n t e r   t h e   f l a g`

This shows the script displays a dialog asking for flag input.

---

## Phase 5: Finding Target Values

### Identify Key Functions

```bash
grep -n "^Function name" inner_disasm.txt
```

**Output:**
```
28:Function name : <...main...>
108:Function name : b'Iidabashi'     ← Main validator
576:Function name : b'Roppongi'
613:Function name : b'Otemachi'
625:Function name : b'Kanda'          ← Hash check
1009:Function name : b'Sugamo'        ← Hash check
1297:Function name : b'Jimbocho'
1309:Function name : b'trimNSString'
1327:Function name : b'splitNSString'
1355:Function name : b'Shimbashi'     ← Encryption!
1458:Function name : b'Ginza'         ← Checksum
1499:Function name : b'stripWhitespace'
1597:Function name : b'split'
```

### Extract Target Array

```bash
sed -n '168,183p' inner_disasm.txt
```

**Output:**
```
00042 PushLiteralExtended 18 # <Value type=fixnum value=0x72>
00045 PushLiteralExtended 19 # <Value type=fixnum value=0x83>
00048 PushLiteralExtended 20 # <Value type=fixnum value=0x7f>
0004b PushLiteral 9 # <Value type=fixnum value=0x7d>
0004c PushLiteralExtended 21 # <Value type=fixnum value=0x78>
...
00073 MakeVector
00074 Push1
00075 MakeVector
00076 GetData
00077 PopVariable [var_11]  ← Stored in var_11
```

### How to Identify Target Values

**Pattern recognition:**
1. **16 consecutive hex pushes** (0x72, 0x83, 0x7f... 0x44)
2. **Followed by `MakeVector`** - creates an array
3. **Stored in variable** `var_11`

**Why 16 bytes?**
- Flag format: `SECCON{????????????????}`
- Total: 24 chars
- Prefix: 7 chars (`SECCON{`)
- Suffix: 1 char (`}`)
- **Middle: 16 chars** ← This is what gets encrypted

### Extract All Values

```bash
sed -n '168,183p' inner_disasm.txt | grep -oP '0x[0-9a-f]+'
```

**Target array:**
```
0x72, 0x83, 0x7f, 0x7d, 0x78, 0x82, 0x74, 0x85,
0x78, 0x81, 0x87, 0x75, 0x86, 0x81, 0x4b, 0x44
```

---

## Phase 6: Identifying Validation Functions

### Trace Function Calls in Iidabashi

```bash
sed -n '108,600p' inner_disasm.txt | grep "PositionalMessageSend"
```

**Output:**
```
00003 PositionalMessageSend 0 # b'Jimbocho'
0000c PositionalMessageSend 1 # b'trimNSString'
000cc PositionalMessageSend 50 # b'Roppongi'
000d5 PositionalMessageSend 51 # b'Otemachi'
0018f PositionalMessageSend 62 # b'Shimbashi'    ← Encryption!
001ab PositionalMessageSend 63 # b'Ginza'        ← Checksum
001c4 PositionalMessageSend 64 # b'Kanda'        ← Hash
0026a PositionalMessageSend 66 # b'Sugamo'       ← Hash
```

### Validation Flow

```
User Input
    ↓
Jimbocho (convert to string)
    ↓
trimNSString (remove whitespace)
    ↓
Check: hasPrefix("SECCON{")
Check: hasSuffix("}")
Check: length == 24
    ↓
Extract middle 16 characters
    ↓
Shimbashi(middle, 13, 6843, 6856) → Encrypt
    ↓
Compare with target array [0x72, 0x83, ...]
    ↓
Ginza(middle) → Checksum validation
Kanda(middle) → Hash validation
Sugamo(middle) → Hash validation
```

**Key insight:** `Shimbashi` is the encryption function we need to reverse.

---

## Phase 7: Reversing Shimbashi Encryption

### View Shimbashi Function

```bash
sed -n '1355,1456p' inner_disasm.txt
```

**Function signature:**
```
Function name : b'Shimbashi'
Function arguments:  [b'washingtondc', b'colorado', b'idaho', b'kansas']
```

### Decode the Variables

Looking at how Iidabashi calls Shimbashi:

```
var_0 (washingtondc) = middle 16 chars of input
var_1 (colorado) = 13
var_2 (idaho) = 6843 (0x1abb)
var_3 (kansas) = 6856 (0x1ac8)
```

**Calculate var_5:**
```
00005 PushVariable [var_3 (b'kansas')]
00006 PushVariable [var_2 (b'idaho')]
00007 Subtract
00008 PushLiteral 0 # <Value type=fixnum value=0x100>
00009 Remainder

var_5 = (6856 - 6843) % 256 = 13
```

### Understanding the Encryption Loop

**Lines 0x0d-0x70: Main loop**

```
0001b RepeatInCollection  ← Start loop over each character
```

**For each character:**

1. **Get character code (lines 0x042-0x047):**
```
00042 PushVariable [var_9]  ← Current character
00044 MessageSend 6 # 'shor'  ← Convert to short (ASCII code)
```

2. **Calculate dynamic offset k (lines 0x04b-0x056):**
```
0004b PushVariable [var_5]     ← 13
0004c PushVariable [var_7]     ← loop index (0, 1, 2, ...)
0004d Push3
0004e Remainder               ← index % 3
0004f Push1
00050 Add                     ← (index % 3) + 1
00051 Multiply                ← 13 * ((index % 3) + 1)
00052 PushLiteral 7 # 0xb
00053 Remainder               ← % 11

k = (13 * ((index % 3) + 1)) % 11
```

3. **Encrypt character (lines 0x057-0x05b):**
```
00057 PushVariable [var_10]    ← char_code
00058 PushVariable [var_1]     ← 13 (colorado)
00059 Add                      ← char_code + 13
0005a PushVariable [var_11]    ← k
0005b Add                      ← char_code + 13 + k

encrypted = char_code + 13 + k
```

### Complete Algorithm

```python
var_5 = 13  # (6856 - 6843) % 256
colorado = 13

for i, character in enumerate(input):
    char_code = ord(character)
    k = (13 * ((i % 3) + 1)) % 11
    encrypted = (char_code + 13 + k) % 256
    output.append(encrypted)
```

### Why Index is 1-Based

Looking at the loop structure, AppleScript's RepeatInCollection typically uses 1-based indexing. Testing both confirms 1-based works:

```python
# 0-based: k = (13 * ((0 % 3) + 1)) % 11 = 2
# 1-based: k = (13 * ((1 % 3) + 1)) % 11 = 4
```

---

## Phase 8: Writing the Solver

### Reverse the Encryption

To decrypt: `original = encrypted - 13 - k`

### Create Solver Script

```bash
cd ~/seccon14CTF-2025/aeppel/applescript-disassembler
nano solve.py
```

**solve.py:**
```python
#!/usr/bin/env python3

# Target encrypted values from var_11
target = [
    0x72, 0x83, 0x7f, 0x7d, 0x78, 0x82, 0x74, 0x85,
    0x78, 0x81, 0x87, 0x75, 0x86, 0x81, 0x4b, 0x44
]

flag_middle = ""

for i, encrypted in enumerate(target):
    # AppleScript uses 1-based indexing
    index = i + 1
    
    # Calculate the dynamic offset
    k = (13 * (index % 3 + 1)) % 11
    
    # Decrypt
    original = encrypted - 13 - k
    
    # Convert to character
    flag_middle += chr(original)

# Construct full flag
flag = f"SECCON{{{flag_middle}}}"
print(flag)

# Verify checksum (Ginza function checks sum % 256 == 0x5f)
total = sum(ord(c) for c in flag_middle)
if total % 256 == 0x5f:
    print("✓ Ginza checksum passed")
else:
    print(f"✗ Ginza checksum failed: {total % 256} != 0x5f")
```

### Run the Solver

```bash
python3 solve.py
```

**Output:**
```
SECCON{applescriptfun<3}
✓ Ginza checksum passed
```

---

## Key Learnings

### Reverse Engineering Methodology

1. **Always start with reconnaissance:**
   - `file` - Identify file type
   - `strings` - Extract readable text
   - `hexdump` - Check magic bytes and structure

2. **Look for patterns:**
   - Repeated values (substitution tables)
   - Constants (encryption keys)
   - Function names (logic flow)

3. **Trace data flow:**
   - Input → Processing → Comparison
   - Find where validation happens
   - Identify encryption functions

### Why These Commands Work

**Without seeing writeups, you discover them by:**

1. **File analysis needs:** → search "how to analyze binary files" → find `file`, `strings`, `hexdump`
2. **Decompilation needs:** → search "applescript decompiler" → find disassembler tools
3. **Pattern extraction:** → use `grep`, `sed`, `awk` to find specific data

**The key insight:** Compiled code always has:
- String literals (error messages, prompts)
- Comparison operations (validation checks)
- Mathematical operations (encryption)

### Common CTF Techniques Used

1. **Nested obfuscation:** Script within script
2. **Anti-analysis:** Platform-specific format (macOS only)
3. **Substitution cipher:** Multiple encoding layers
4. **Checksum validation:** Multiple validation functions
5. **Magic constants:** Values like 13, 6843, 6856 are clues

### How to Approach Similar Challenges

1. **Don't panic about unknown formats** - Tools exist for everything
2. **Read disassembly systematically** - Start from entry point, trace calls
3. **Look for arrays/vectors** - Often contain target values
4. **Identify math operations** - Usually reveal encryption logic
5. **Test hypotheses** - Write small scripts to verify understanding

---

## Complete Command Reference

### Phase 1: Reconnaissance
```bash
file 1.scpt
strings 1.scpt | head -50
strings 1.scpt | grep -E "^[a-z]+$"
hexdump -C 1.scpt | head -3
```

### Phase 2: Setup Disassembler
```bash
git clone https://github.com/Jinmo/applescript-disassembler
cd applescript-disassembler
python3 disassembler.py ../1.scpt > ../disassembled.txt
```

### Phase 3: Extract Inner Script
```bash
python3 extract.py
dd if=raw.bin of=inner.scpt bs=1 skip=4
file inner.scpt
```

### Phase 4: Disassemble Inner
```bash
python3 disassembler.py inner.scpt > inner_disasm.txt
wc -l inner_disasm.txt
```

### Phase 5: Find Targets
```bash
grep -n "^Function name" inner_disasm.txt
sed -n '168,183p' inner_disasm.txt | grep -oP '0x[0-9a-f]+'
```

### Phase 6: Trace Functions
```bash
sed -n '108,600p' inner_disasm.txt | grep "PositionalMessageSend"
```

### Phase 7: Analyze Encryption
```bash
sed -n '1355,1456p' inner_disasm.txt
```

### Phase 8: Solve
```bash
python3 solve.py
```

---

## Conclusion

This challenge taught us:
- How to work with unfamiliar binary formats
- Nested obfuscation techniques
- Systematic reverse engineering methodology
- The importance of understanding data flow in bytecode

**Flag:** `SECCON{applescriptfun<3}`

The flag itself is a playful nod to AppleScript - acknowledging that despite the difficulty, working with it can be "fun" (with a heart emoji `<3`).
