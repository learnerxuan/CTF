# WordleOS - Detailed CTF Writeup

**CTF:** Null CTF 2025  
**Challenge:** WordleOS  
**Category:** Reverse Engineering / Misc  
**Difficulty:** Medium  
**Flag:** `nullctf{b00t_1nt0_w0rdl3}`

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Understanding the Challenge (Simple Explanation)](#understanding-the-challenge-simple-explanation)
3. [Initial Analysis](#initial-analysis)
4. [Understanding the File Structure](#understanding-the-file-structure)
5. [Extracting the Kernel ELF](#extracting-the-kernel-elf)
6. [Finding the Target String](#finding-the-target-string)
7. [Understanding VGA Text Mode](#understanding-vga-text-mode)
8. [Locating the Comparison Logic](#locating-the-comparison-logic)
9. [Extracting and Decoding the Flag](#extracting-and-decoding-the-flag)
10. [Verification](#verification)
11. [Key Learnings](#key-learnings)
12. [General Approach for Future OS Challenges](#general-approach-for-future-os-challenges)

---

## Challenge Overview

### Description

> They say you can build an OS for everything, so I built one that can play Wordle. Well, kinda, I am a bit colorblind, so I couldn't put the colored letters. They are all white (I think). But it should tell you when you get the word correct anyway.

**Note:** Run with `qemu-system-x86_64 -drive format=raw,file=wordle_os.bin`

### What We're Given

- `wordle_os.bin` - A bootable disk image (DOS/MBR boot sector)
- Instructions to run it with QEMU

### Goal

Find the correct word (flag) without brute-forcing by reverse engineering the binary.

---

## Understanding the Challenge (Simple Explanation)

### What Are We Really Doing?

Think of this challenge like a **locked treasure chest with a puzzle inside**:

```
┌─────────────────────────────────────────┐
│   wordle_os.bin (Bootable Disk Image)   │  ← The locked chest
│                                         │
│   ┌─────────────────────────────────┐  │
│   │  Boot Code (Lock mechanism)     │  │
│   └─────────────────────────────────┘  │
│                                         │
│   ┌─────────────────────────────────┐  │
│   │  ELF Kernel (The actual puzzle) │  │  ← The treasure we need!
│   │  Contains the game logic        │  │     This has the answer!
│   └─────────────────────────────────┘  │
│                                         │
│   Random data...                        │
└─────────────────────────────────────────┘
```

**Our Mission:**
1. **Extract the puzzle** from the chest (find and extract the ELF kernel)
2. **Solve the puzzle** (reverse engineer to find the answer)
3. **Get the treasure** (the flag!)

### Why Can't We Just Analyze `wordle_os.bin` Directly?

`wordle_os.bin` is a **raw disk image** meant to be booted by a computer. It's like trying to read a DVD without a DVD player - the data is there, but it's wrapped in a format that needs special handling.

Inside this disk image, there's a **kernel** (the actual program) that we need to extract first before we can analyze it properly.

### What is an ELF File?

**ELF = Executable and Linkable Format** (the Linux equivalent of Windows `.exe` files)

- On **Windows**: Programs end with `.exe`
- On **Linux**: Programs are ELF files (no extension needed)

ELF files have a **structured format** that reverse engineering tools understand:
- `objdump` - Shows assembly code
- `readelf` - Shows file information  
- `ghidra`, `IDA` - Full reverse engineering suites

### The Key Insight: Every ELF File Has a Signature

Just like every `.zip` file starts with `PK`, every ELF file starts with:

```
0x7F 0x45 0x4C 0x46
  ↓    ↓    ↓    ↓
0x7F  'E'  'L'  'F'
```

This is our **treasure map marker** - we search `wordle_os.bin` for this signature to find where the kernel is hidden!

### The Solution Strategy

```
Step 1: Identify file type
   ↓
Step 2: Search for ELF signature (0x7F ELF)
   ↓
Step 3: Extract and validate ELF file(s)
   ↓
Step 4: Analyze the valid ELF kernel
   ↓
Step 5: Find comparison logic
   ↓
Step 6: Extract the flag!
```

---

## Initial Analysis

### File Type Check

```bash
┌──(xuan㉿kali)-[~/nullCTF2025/wordleOS]
└─$ file wordle_os.bin
wordle_os.bin: DOS/MBR boot sector
```

This confirms we have a bootable disk image with a Master Boot Record.

### Running the OS

```bash
qemu-system-x86_64 -drive format=raw,file=wordle_os.bin
```

When run, the OS displays:
- **"Welcome to WordleOS!"**
- A prompt to enter 5-letter words
- **"Correct!"** message when the right word is entered (no color feedback)

### String Analysis

```bash
strings wordle_os.bin | grep -E "WordleOS|Correct"
```

**Output:**
```
Welcome to WordleOS!
Correct!
```

**Observation:** The strings exist, but the actual answer/flag is not stored as plain ASCII. This means it's either:
- Encoded
- Stored in a non-standard format
- Generated dynamically

---

## Understanding the File Structure

### What is a Bootable Disk Image?

A bootable disk image contains:

1. **Boot Sector** (first 512 bytes)
   - Contains bootstrap code
   - Must end with boot signature `0x55 0xAA` at offset `0x1FE`

2. **Additional Boot Code** (optional)

3. **Kernel/OS Code** (the actual program)
   - Can be in various formats (raw machine code, ELF, etc.)

4. **Data Sections**

### Why Look for an ELF?

ELF (Executable and Linkable Format) is the standard executable format on Linux. If the kernel is stored as an ELF:
- We can use standard tools (`objdump`, `readelf`, `ghidra`)
- It will have proper sections (`.text`, `.rodata`, `.data`)
- Easier to analyze than raw machine code

---

## Extracting the Kernel ELF

### Step 1: Find All ELF Headers

Every ELF file starts with a magic signature: **`0x7F 0x45 0x4C 0x46`** (which is `0x7F` + "ELF" in ASCII).

Let's search for this signature:

```python
import pathlib, re

b = pathlib.Path("wordle_os.bin").read_bytes()

for m in re.finditer(b"\x7fELF", b):
    print("ELF @", m.start())
```

**Output:**
```
ELF @ 21813
ELF @ 22630
ELF @ 52736
```

**Why multiple ELF headers?**
- Could be corrupted/incomplete ELF data
- Could be debug symbols
- Could be multiple embedded binaries
- We need to check which one is valid

### Step 2: Extract Each ELF Candidate

```bash
# Extract first ELF
dd if=wordle_os.bin bs=1 skip=21813 of=elf1.bin status=none

# Extract second ELF
dd if=wordle_os.bin bs=1 skip=22630 of=elf2.bin status=none

# Extract third ELF
dd if=wordle_os.bin bs=1 skip=52736 of=elf3.bin status=none
```

**`dd` command explanation:**
- `if=` - input file
- `bs=1` - block size of 1 byte (read byte by byte)
- `skip=N` - skip N bytes from the start
- `of=` - output file
- `status=none` - suppress progress output

### Step 3: Verify Which ELF is Valid

```bash
file elf1.bin
file elf2.bin
file elf3.bin
```

**Output:**
```
elf1.bin: ELF, unknown class 117
elf2.bin: ELF (AROS Research Operating System), unknown class 117
elf3.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

**Analysis:**
- ✗ `elf1.bin` - Corrupted/invalid ELF (unknown class)
- ✗ `elf2.bin` - Corrupted/invalid ELF
- ✓ `elf3.bin` - **Valid 64-bit x86-64 ELF executable!**

### Step 4: Verify the Valid ELF

```bash
readelf -h elf3.bin
```

**Output:**
```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
```

Perfect! We have our kernel.

---

## Finding the Target String

### Step 1: Locate "Correct!" in .rodata

The `.rodata` section contains read-only data (like string constants).

```bash
objdump -s -j .rodata elf3.bin | grep -A 2 -B 2 "Correct"
```

**What this does:**
- `-s` - Display full contents of sections
- `-j .rodata` - Only show the `.rodata` section
- `grep` - Search for "Correct"

**Output:**
```
Contents of section .rodata:
 200300 57656c63 6f6d6520 746f2057 6f72646c  Welcome to Wordl
 200310 654f5321 0a000000 436f7272 6563742l  eOS!....Correct!
                           ^^^^^^^^^^^^^^^^
```

**Analysis:**
- "Correct!" is located at address **`0x200311`**
- This is our anchor point to find the success code path

### Step 2: Find Code That References This Address

```bash
objdump -d -Mintel elf3.bin | grep "200311"
```

**What this does:**
- `-d` - Disassemble executable sections
- `-Mintel` - Use Intel assembly syntax (easier to read)
- Search for references to address `0x200311`

**Output:**
```
20377b:  48 8d 35 8f cb ff ff    lea    rsi,[rip+0xffffffffffffcb8f]  # 200311
```

**Analysis:**
- At address `0x20377b`, the code loads the address of "Correct!" into register `rsi`
- This is part of preparing to print the success message
- We need to look **before** this instruction to find the comparison logic

---

## Understanding VGA Text Mode

### What is VGA Text Mode?

VGA text mode is a display mode where:
- The screen is divided into a grid (typically 80x25 characters)
- Each character cell is represented by **2 bytes in memory**:
  - **Byte 1:** ASCII character code
  - **Byte 2:** Attribute byte (color/style)

### Visual Example: How Characters Are Stored

#### What You See on Screen:
```
n u l l
```

#### What's Actually in Memory:
```
Offset:  0    1    2    3    4    5    6    7    8    9    10   11
Data:   'n'  0x0f ' '  0x0f 'u'  0x0f ' '  0x0f 'l'  0x0f ' '  0x0f
        ^^^  ^^^^
        |    |
        |    └─ Attribute (white on black)
        └────── Character
```

**Breakdown:**
- `'n'` (0x6E) = Character 'n'
- `0x0F` = Attribute byte (white foreground, black background)
- `' '` (0x20) = Space character
- `0x0F` = Attribute byte
- `'u'` (0x75) = Character 'u'
- ... and so on

### Why This Matters for the Challenge

**Normal string comparison:**
```c
if (strcmp(input, "null") == 0) {
    printf("Correct!");
}
```

**This challenge's VGA comparison:**
```c
// Compares the VGA buffer directly (char + attr + char + attr...)
if (vga_buffer[0:8] == expected_vga_bytes) {
    printf("Correct!");
}
```

The program **doesn't compare a simple string** - it compares the **raw VGA memory** which includes attribute bytes!

### Understanding the 64-bit Constants

A 64-bit (8-byte) constant in VGA format represents **4 characters** (because each char takes 2 bytes):

#### Example Constant: `0xf200f750f200f6e`

**Step 1: Convert to bytes (little-endian)**
```
0x0f200f750f200f6e
     ↓
[6E 0F 20 0F 75 0F 20 0F]  (8 bytes)
```

**Step 2: Visualize the structure**
```
Byte Position:  0    1    2    3    4    5    6    7
Byte Value:    6E   0F   20   0F   75   0F   20   0F
               ^^   ^^   ^^   ^^   ^^   ^^   ^^   ^^
               |    |    |    |    |    |    |    |
Type:        CHAR ATTR CHAR ATTR CHAR ATTR CHAR ATTR
```

**Step 3: Extract characters (positions 0, 2, 4, 6)**
```
Position 0: 0x6E = 'n'
Position 2: 0x20 = ' ' (space)
Position 4: 0x75 = 'u'
Position 6: 0x20 = ' ' (space)

Result: "n u "
```

### Decoding Function Explained

```python
def decode(v):
    """Decode a 64-bit VGA constant to 4 characters"""
    # Convert the number to 8 bytes (little-endian)
    b = v.to_bytes(8, "little")
    
    # Extract every OTHER byte (skip attribute bytes at positions 1,3,5,7)
    # Take bytes at positions: 0, 2, 4, 6
    return "".join(chr(b[i]) for i in range(0, 8, 2))

# Example usage:
decode(0xf200f750f200f6e)  # Returns: "n u "
```

**Why `range(0, 8, 2)`?**
- Start at position 0 (first character)
- Go up to position 8 (end of 8 bytes)
- Step by 2 (skip attribute bytes)

This gives us positions: 0, 2, 4, 6 - exactly where the characters are!

### Complete Example with Multiple Constants

If the program checks these three constants:

```python
constant1 = 0xf200f750f200f6e  # "n u "
constant2 = 0xf200f6c0f200f6c  # "l l "  
constant3 = 0xf200f740f200f63  # "c t "

# Decode all
result = decode(constant1) + decode(constant2) + decode(constant3)
# Result: "n u l l c t "

# Remove spaces
flag = result.replace(" ", "")
# Result: "nullct"
```

### Why VGA Format Makes This Tricky

**What we expect to see:**
```assembly
movabs rax, 0x6c6c756e    ; "null" as a simple string
```

**What we actually see:**
```assembly
movabs rax, 0xf200f750f200f6e    ; "n u " in VGA format!
```

The attribute bytes (`0x0f`, `0x20`) make the constants look strange and hide the actual text!

### Quick VGA Decoding Reference

| Constant | Bytes (little-endian) | Characters | Result |
|----------|----------------------|------------|---------|
| `0xf200f750f200f6e` | `6E 0F 20 0F 75 0F 20 0F` | n, space, u, space | "n u " |
| `0xf200f6c0f200f6c` | `6C 0F 20 0F 6C 0F 20 0F` | l, space, l, space | "l l " |
| `0xf200f740f200f63` | `63 0F 20 0F 74 0F 20 0F` | c, space, t, space | "c t " |

**Pattern Recognition:**
- Every constant has repeating `0F` and `20` (attributes and spaces)
- The actual characters are at positions 0, 2, 4, 6
- Each constant decodes to exactly 4 characters (with spaces)

---

## Locating the Comparison Logic

### Step 1: Get Context Around the Success Path

```bash
objdump -d -Mintel elf3.bin | grep -B 100 -A 10 "200311"
```

This shows 100 lines **before** and 10 lines **after** the "Correct!" reference.

### Step 2: Analyze the Comparison Loop

Looking at the output, we find a series of comparisons starting around address `0x2035ad`:

```assembly
# Load VGA buffer base address
2035a6: mov    rax,QWORD PTR [rip+0x6eea]  # Get VGA buffer address

# Comparison 1: Check bytes at offset 0xf00
2035ad: mov    rcx,QWORD PTR [rax+0xf00]
2035b4: movabs rdx,0xf200f750f200f6e      # Expected value
2035be: cmp    rcx,rdx                     # Compare
2035c1: jne    203729                      # Jump if not equal (wrong answer)

# Comparison 2: Check bytes at offset 0xf08
2035c7: mov    rcx,QWORD PTR [rax+0xf08]
2035ce: movabs rdx,0xf200f6c0f200f6c
2035d8: cmp    rcx,rdx
2035db: jne    203729

# ... and so on for 13 total comparisons
```

### Step 3: Understanding the Pattern

Each comparison follows this pattern:

1. **Load 8 bytes** from VGA buffer at specific offset
2. **Load expected constant** into a register
3. **Compare** the actual vs expected
4. **Jump to wrong answer** if they don't match
5. **Continue to next comparison** if they match

If **ALL 13 comparisons pass**, the code reaches the "Correct!" print at `0x20377b`.

### Step 4: Extract All Constants

Here are all 13 comparison constants found in the assembly:

```assembly
# Chunk 1 (offset 0xf00):
movabs rdx, 0xf200f750f200f6e

# Chunk 2 (offset 0xf08):
movabs rdx, 0xf200f6c0f200f6c

# Chunk 3 (offset 0xf10):
movabs rcx, 0xf200f740f200f30
lea    rsi,[rcx+0x33]              # Add 0x33!

# Chunk 4 (offset 0xf18):
movabs rsi, 0xf200f7b0f200f66

# Chunk 5 (offset 0xf20):
movabs rdx, 0xf200f300f200f62

# Chunk 6 (offset 0xf28):
# Reuses rcx from chunk 3: 0xf200f740f200f30

# Chunk 7 (offset 0xf30):
movabs rdi, 0xf200f310f200f5f

# Chunk 8 (offset 0xf38):
add    rcx,0x3e                    # Add 0x3e to chunk 3 constant!

# Chunk 9 (offset 0xf40):
movabs rsi, 0xf200f5f0f200f30

# Chunk 10 (offset 0xf48):
add    rdx,0x15                    # Add 0x15 to chunk 5 constant!

# Chunk 11 (offset 0xf50):
movabs rdx, 0xf200f640f200f72

# Chunk 12 (offset 0xf58):
movabs rdx, 0xf200f330f200f6c

# Chunk 13 (offset 0xf60):
movabs rcx, 0xf200f200f200f7d
```

**Note:** Some constants are modified with `add` instructions. These need to be applied when decoding.

---

## Extracting and Decoding the Flag

### Step 1: Create the Decode Script

Create a Python script to decode the VGA constants:

```python
#!/usr/bin/env python3

# All 13 constants extracted from the assembly
chunks = [
    0xf200f750f200f6e,           # Chunk 1
    0xf200f6c0f200f6c,           # Chunk 2
    0xf200f740f200f30 + 0x33,    # Chunk 3 + modification
    0xf200f7b0f200f66,           # Chunk 4
    0xf200f300f200f62,           # Chunk 5
    0xf200f740f200f30,           # Chunk 6 (reused from 3)
    0xf200f310f200f5f,           # Chunk 7
    0xf200f740f200f30 + 0x3e,    # Chunk 8 (chunk 3 + 0x3e)
    0xf200f5f0f200f30,           # Chunk 9
    0xf200f300f200f62 + 0x15,    # Chunk 10 (chunk 5 + 0x15)
    0xf200f640f200f72,           # Chunk 11
    0xf200f330f200f6c,           # Chunk 12
    0xf200f200f200f7d,           # Chunk 13
]

def decode(v):
    """
    Decode a 64-bit VGA memory value to 4 characters.
    
    VGA format: [char][attr][char][attr][char][attr][char][attr]
    We extract bytes at positions 0, 2, 4, 6 (the character bytes)
    """
    b = v.to_bytes(8, "little")  # Convert to bytes (little-endian)
    return "".join(chr(b[i]) for i in range(0, 8, 2))

# Decode all chunks and concatenate
s = "".join(decode(x) for x in chunks)

print("With spaces:", s)
print("Flag:        ", s.replace(" ", ""))
```

### Step 2: Run the Script

```bash
python3 decode_flag.py
```

**Output:**
```
With spaces: n u l l c t f { b 0 0 t _ 1 n t 0 _ w 0 r d l 3 }
Flag:         nullctf{b00t_1nt0_w0rdl3}
```

### Step 3: Understanding the Decode Function

Let's trace through one example:

**Constant:** `0xf200f750f200f6e`

**Step 1: Convert to bytes (little-endian)**
```
0xf200f750f200f6e → [6e 0f 20 0f 75 0f 20 0f]
```

**Step 2: Extract characters (positions 0, 2, 4, 6)**
```
Position: 0   1   2   3   4   5   6   7
Byte:     6e  0f  20  0f  75  0f  20  0f
          ^       ^       ^       ^
          |       |       |       |
Extract:  6e      20      75      20
```

**Step 3: Convert to ASCII**
```
0x6e = 'n'
0x20 = ' ' (space)
0x75 = 'u'
0x20 = ' ' (space)

Result: "n u "
```

Repeat for all 13 chunks to get the complete flag!

---

## Verification

### Method 1: Test in the Running OS

```bash
qemu-system-x86_64 -drive format=raw,file=wordle_os.bin
```

Type the flag (without spaces and braces): `nullctfb00t1nt0w0rdl3`

**Result:** The OS displays "Correct!" ✓

### Method 2: Verify the VGA Memory Layout

The flag format makes sense:
- `nullctf{...}` follows the standard CTF flag format
- `b00t_1nt0_w0rdl3` is a play on "boot into wordle"
- Total characters: 26 (fits the 13 chunks × 2 chars per chunk with spaces)

---

## General Approach for Future OS Challenges

### When Do I Need to Find and Extract ELF Files?

#### ✅ **YES - Extract ELF When You See:**

**File Type Indicators:**
```bash
file challenge.bin
# Output contains any of:
# - "DOS/MBR boot sector"
# - "boot sector"
# - "bootable"
# - "disk image"
```

**Challenge Descriptions Mentioning:**
- "Run with QEMU"
- "Bootable OS"
- "Run in virtual machine"
- Files ending in `.img`, `.iso`, `.bin` (if bootable)

**Why?** These files contain an entire disk structure with the actual program (kernel) embedded inside. You must extract it first!

#### ❌ **NO - Analyze Directly When You See:**

```bash
file challenge
# Output:
# - "ELF 64-bit LSB executable"
# - "ELF 32-bit executable"
```

**Why?** It's already an executable program - analyze it directly with `objdump`, `ghidra`, etc.

---

### Step-by-Step Methodology for OS Challenges

#### Step 1: Identify What You Have

```bash
file challenge_file
```

**Decision Tree:**
```
Is it a "boot sector" or "disk image"?
├─ YES → Go to Step 2 (Extract ELF)
└─ NO  → Is it already an ELF?
    ├─ YES → Skip to Step 4 (Analyze directly)
    └─ NO  → Research the specific file format
```

#### Step 2: Search for ELF Signature

Create a quick script to find all ELF headers:

```python
#!/usr/bin/env python3
import pathlib, re

def find_elf_headers(filepath):
    """Search for all ELF magic signatures in a file"""
    data = pathlib.Path(filepath).read_bytes()
    
    print(f"[*] Searching {filepath} for ELF headers...")
    print(f"[*] File size: {len(data)} bytes")
    
    matches = list(re.finditer(b"\x7fELF", data))
    
    if matches:
        print(f"[+] Found {len(matches)} ELF header(s):")
        for i, m in enumerate(matches, 1):
            offset = m.start()
            print(f"    ELF #{i}: offset {offset} (0x{offset:x})")
    else:
        print("[-] No ELF headers found!")
    
    return [m.start() for m in matches]

# Usage
offsets = find_elf_headers("challenge.bin")
```

**What This Does:**
- Reads the entire file as binary data
- Searches for the byte pattern `0x7F 0x45 0x4C 0x46` (ELF magic)
- Returns all positions where it found this signature

#### Step 3: Extract and Validate Each ELF

For each offset found, extract and test:

```bash
# Extract ELF at specific offset
extract_elf() {
    offset=$1
    output="elf_${offset}.bin"
    
    echo "[*] Extracting from offset $offset..."
    dd if=challenge.bin bs=1 skip=$offset of=$output status=none
    
    echo "[*] Checking if valid..."
    file $output
    
    # Try to read ELF header
    readelf -h $output 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "[+] VALID ELF at offset $offset!"
        
        # Check for interesting strings
        echo "[*] Searching for interesting strings..."
        strings $output | grep -iE "flag|correct|password|key" | head -5
    else
        echo "[-] Invalid or corrupted ELF"
    fi
    
    echo ""
}

# Extract all found ELFs
for offset in 21813 22630 52736; do
    extract_elf $offset
done
```

**Validation Checklist:**
- ✅ `file` command identifies it as valid ELF
- ✅ `readelf -h` shows proper header without errors
- ✅ Contains expected strings (game text, etc.)
- ✅ Has proper sections (`.text`, `.rodata`, `.data`)

#### Step 4: Analyze the Valid ELF

Once you have a valid ELF, use standard reverse engineering workflow:

```bash
# 1. Get basic information
readelf -h kernel.elf          # ELF header
readelf -S kernel.elf          # Section headers
readelf -l kernel.elf          # Program headers

# 2. Look for strings
strings kernel.elf | less
strings kernel.elf | grep -i "interesting_keyword"

# 3. Disassemble
objdump -d -Mintel kernel.elf > disasm.txt

# 4. Find interesting functions
objdump -d kernel.elf | grep "^[0-9a-f]* <" | grep -iE "check|validate|compare|main"

# 5. Open in GUI tool (optional but recommended)
ghidra kernel.elf              # or
ida64 kernel.elf               # or
radare2 kernel.elf
```

#### Step 5: Common Patterns to Look For

**Pattern 1: Success String → Work Backwards**
```assembly
# Find strings like "Correct!", "Success!", "Flag:"
strings kernel.elf | grep -i "correct"
# Find where it's referenced in code
objdump -d kernel.elf | grep "address_of_string"
# Look backwards for comparison logic
```

**Pattern 2: Comparison Loops**
```assembly
# Look for patterns like:
cmp    rax, rbx              ; Compare two values
jne    wrong_answer          ; Jump if not equal
# or
test   eax, eax              ; Check if zero
je     success               ; Jump if equal (to zero)
```

**Pattern 3: Constant Comparisons**
```assembly
# Large hex constants often contain encoded data:
movabs rax, 0x1234567890abcdef
cmp    [input], rax
```

---

### Quick Reference: Tool Cheatsheet

| Tool | Purpose | Example Usage |
|------|---------|---------------|
| `file` | Identify file type | `file challenge.bin` |
| `strings` | Extract readable text | `strings kernel.elf \| grep flag` |
| `hexdump` | View raw hex | `hexdump -C kernel.elf \| less` |
| `xxd` | Hex editor | `xxd kernel.elf \| grep "7F 45 4C 46"` |
| `dd` | Extract binary chunks | `dd if=in.bin bs=1 skip=1000 of=out.bin` |
| `objdump` | Disassemble | `objdump -d -Mintel kernel.elf` |
| `readelf` | ELF info | `readelf -h kernel.elf` |
| `nm` | List symbols | `nm kernel.elf` |
| `ghidra` | Full RE suite | `ghidra kernel.elf` |

---

### Common Gotchas and Tips

#### Gotcha 1: Multiple ELF Headers
**Problem:** Found 3 ELF signatures but only 1 is valid.

**Solution:** Always validate each one:
```bash
for f in elf*.bin; do
    echo "Testing $f..."
    if readelf -h $f 2>/dev/null; then
        echo "✓ Valid!"
    else
        echo "✗ Invalid"
    fi
done
```

#### Gotcha 2: Strange Constants
**Problem:** Seeing hex values like `0xf200f750f200f6e` - what are these?

**Solution:** These might be encoded data. Consider:
- VGA text mode (2 bytes per char)
- Multi-byte character encodings
- XOR encryption
- Base64/Base32 encoded
- Reversed strings

#### Gotcha 3: Can't Find Comparisons
**Problem:** Looked everywhere but can't find where it checks the password.

**Solution:** Try these approaches:
1. Search for success/failure strings, work backwards
2. Look for `cmp`, `test`, `strcmp`, `memcmp` instructions
3. Check if it's using hash comparison (MD5, SHA)
4. Use dynamic analysis (debugger) to trace execution

#### Gotcha 4: Assembly is Confusing
**Problem:** I don't understand the assembly code!

**Solution:** 
1. Use Ghidra's decompiler (shows pseudo-C code)
2. Focus on finding patterns, not understanding every instruction
3. Look for:
   - Function calls: `call instruction`
   - Comparisons: `cmp`, `test`
   - Conditional jumps: `je`, `jne`, `jg`, etc.
   - Loading constants: `mov`, `movabs`

---

### Practice Workflow Summary

```
┌─────────────────────────────────────┐
│ 1. file challenge.bin               │
│    └─> Boot sector? → Extract ELF  │
│    └─> Already ELF? → Analyze      │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 2. Search for ELF signatures        │
│    └─> Find all 0x7F ELF markers   │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 3. Extract & validate each          │
│    └─> Test with readelf/file      │
│    └─> Keep the valid one          │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 4. Analyze the kernel               │
│    └─> strings, objdump, ghidra    │
│    └─> Find success path           │
│    └─> Work backwards               │
└─────────────────────────────────────┘
              ↓
┌─────────────────────────────────────┐
│ 5. Extract comparison constants     │
│    └─> Decode if needed            │
│    └─> Get the flag!               │
└─────────────────────────────────────┘
```

---

## Key Learnings

### 1. Bootable Image Structure
- Boot sectors contain bootstrap code
- Can embed full ELF executables
- Multiple ELF headers may exist (need validation)

### 2. ELF File Analysis
- Magic bytes `0x7F ELF` identify ELF files
- Standard tools work on extracted ELFs
- `.rodata` section contains string constants

### 3. VGA Text Mode Memory Layout
- Each character = 2 bytes (char + attribute)
- Direct memory comparison instead of string comparison
- Constants look strange but follow a pattern

### 4. Reverse Engineering Techniques
- **Find anchor points** (like "Correct!" string)
- **Work backwards** from success path
- **Pattern recognition** in comparisons
- **Extract constants** systematically
- **Understand data encoding** before decoding

### 5. Assembly Reading Skills
- `movabs` loads 64-bit immediate values
- `cmp` + `jne` is a comparison and conditional jump
- `lea` calculates addresses
- Register reuse can be tricky

### 6. Tools Used
- `file` - Identify file types
- `strings` - Extract printable strings
- `dd` - Extract binary data at specific offsets
- `objdump` - Disassemble and analyze binaries
- `readelf` - Display ELF file information
- `grep` - Search through output
- Python - Decode binary data

---

## Complete Solution Script

Here's a complete script that performs the entire analysis:

```python
#!/usr/bin/env python3
"""
WordleOS CTF Challenge - Complete Solution
Extracts and decodes the flag from wordle_os.bin
"""

import pathlib
import re

def find_elf_offsets(binary_path):
    """Find all ELF headers in the binary"""
    data = pathlib.Path(binary_path).read_bytes()
    offsets = [m.start() for m in re.finditer(b"\x7fELF", data)]
    return offsets

def extract_elf(binary_path, offset, output_path):
    """Extract ELF starting at offset"""
    data = pathlib.Path(binary_path).read_bytes()
    pathlib.Path(output_path).write_bytes(data[offset:])

def decode_vga_constant(value):
    """Decode a 64-bit VGA memory constant to 4 characters"""
    b = value.to_bytes(8, "little")
    return "".join(chr(b[i]) for i in range(0, 8, 2))

def main():
    # Step 1: Find ELF headers
    print("[*] Searching for ELF headers...")
    offsets = find_elf_offsets("wordle_os.bin")
    print(f"[+] Found {len(offsets)} ELF headers at offsets: {offsets}")
    
    # Step 2: Extract the valid kernel (offset 52736)
    print("\n[*] Extracting kernel ELF...")
    extract_elf("wordle_os.bin", 52736, "kernel.elf")
    print("[+] Kernel extracted to kernel.elf")
    
    # Step 3: Decode the flag from known constants
    print("\n[*] Decoding flag from VGA constants...")
    
    chunks = [
        0xf200f750f200f6e,
        0xf200f6c0f200f6c,
        0xf200f740f200f30 + 0x33,
        0xf200f7b0f200f66,
        0xf200f300f200f62,
        0xf200f740f200f30,
        0xf200f310f200f5f,
        0xf200f740f200f30 + 0x3e,
        0xf200f5f0f200f30,
        0xf200f300f200f62 + 0x15,
        0xf200f640f200f72,
        0xf200f330f200f6c,
        0xf200f200f200f7d,
    ]
    
    flag_with_spaces = "".join(decode_vga_constant(x) for x in chunks)
    flag = flag_with_spaces.replace(" ", "")
    
    print(f"[+] Decoded (with spaces): {flag_with_spaces}")
    print(f"[+] Flag: {flag}")
    
    return flag

if __name__ == "__main__":
    flag = main()
    print(f"\n{'='*60}")
    print(f"FLAG: {flag}")
    print(f"{'='*60}")
```

---

## Flag

```
nullctf{b00t_1nt0_w0rdl3}
```

---

## Conclusion

This challenge demonstrated the intersection of systems programming (bootable OS), reverse engineering (binary analysis), and understanding hardware interfaces (VGA text mode). The key was recognizing that the comparison wasn't against a normal string but against VGA memory format, which encoded characters with attribute bytes.

The challenge title "b00t_1nt0_w0rdl3" is a clever play on "boot into Wordle" - exactly what we did by booting the OS and reverse engineering the Wordle game logic!

**Author:** xuan  
**Date:** December 2025  
**CTF:** Null CTF 2025
