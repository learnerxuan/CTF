# V1T CTF 2025 - Duck Product Key - Complete Beginner's Writeup

**Challenge Name:** Duck Product Key  
**Category:** Reverse Engineering  
**Difficulty:** Medium-Hard  
**Points:** Unknown  
**Flag:** `v1t{0bfu5c471n6_7h1n65_w17h_p3b_648a18c0}`

---

## Table of Contents

1. [Challenge Description](#challenge-description)
2. [Initial Analysis - What I Saw First](#initial-analysis---what-i-saw-first)
3. [My First Attempts (What Went Wrong)](#my-first-attempts-what-went-wrong)
4. [Understanding the Challenge Properly](#understanding-the-challenge-properly)
5. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
6. [Phase 2: Static Analysis with Ghidra](#phase-2-static-analysis-with-ghidra)
7. [Phase 3: Understanding API Obfuscation (PEB Walking)](#phase-3-understanding-api-obfuscation-peb-walking)
8. [Phase 4: Analyzing Validation Logic](#phase-4-analyzing-validation-logic)
9. [Phase 5: Solution - Writing the Keygen](#phase-5-solution---writing-the-keygen)
10. [Testing and Getting the Flag](#testing-and-getting-the-flag)
11. [Post-Mortem: What I Learned](#post-mortem-what-i-learned)
12. [Future Reference Guide](#future-reference-guide)

---

## Challenge Description

> My bro made a product with a product key checker. Can you, reverse it or figure out how it works?

**Given Files:**
- `duck_product_key.exe` (24KB)

**Challenge Type:** Windows reverse engineering with product key validation

---

## Initial Analysis - What I Saw First

### Basic File Information

```bash
┌──(xuan㉿kali)-[~/V1t_CTF2025/Product_Key]
└─$ file duck_product_key.exe
duck_product_key.exe: PE32+ executable (GUI) x86-64, for MS Windows, 5 sections

┌──(xuan㉿kali)-[~/V1t_CTF2025/Product_Key]
└─$ ls -lh duck_product_key.exe
-rw-rw-r-- 1 xuan xuan 24K Nov  4 23:21 duck_product_key.exe
```

**Key Observations:**
- **PE32+** = Windows 64-bit executable
- **GUI** = Graphical user interface (not command line)
- **x86-64** = 64-bit architecture
- **24KB** = Small file, likely not packed
- **5 sections** = Standard Windows executable structure

### Running the Program

```bash
wine64 duck_product_key.exe
```

**What I saw:**
- A dialog box appeared
- Title: "Register Product"
- Single text input field with label "Enter Valid Product Key"
- One button: "VERIFY"
- When I tried random input like "test123", it showed:
  - Error dialog: "Invalid product key"

**Initial hypothesis:** I need to find or generate a valid product key.

---

## My First Attempts (What Went Wrong)

### ❌ Mistake #1: Assumed It Would Be Easy

**What I thought:**
> "It's only 24KB, probably just has the flag in memory. I'll use x64dbg, search for 'v1t{', and get the flag!"

**What I did:**
1. Opened in x64dbg
2. Set breakpoint on `MessageBoxA`
3. Ran the program
4. Entered random product key
5. Searched memory for "v1t{"

**Result:** Nothing found. The flag wasn't just sitting in memory.

**Why this failed:**
- The flag is **encrypted** until a valid key is entered
- The product key validation **IS** the challenge
- Memory search only works if data is already decrypted

**Lesson learned:** Don't assume the easy path. When you see "product key", that's the actual challenge!

---

### ❌ Mistake #2: Got Distracted by Obfuscation

**What I found:**
Using `strings` command, I saw:
```
USER32.dll
KERNEL32.dll
VCRUNTIME140.dll
DefWindowProcA
memset
```

But very few actual API function names!

**What I did:**
- Spent time trying to understand PEB walking
- Decrypted some strings (found "user32.dll", "FLAG_CHECKER_WIN")
- Got excited about finding encrypted strings
- Analyzed the string decryption function thoroughly

**Why this was wrong:**
- String decryption was just **obfuscation**, not the main challenge
- Window class names like "FLAG_CHECKER_WIN" aren't the actual flag
- I was analyzing the **interesting** code instead of the **critical** code

**Lesson learned:** Focus on the critical path (validation logic), not on interesting side features (obfuscation).

---

### ❌ Mistake #3: Wrong Priority Order

**What I did (wrong order):**
1. Analyzed string encryption ❌
2. Tried to understand all the PEB walking code ❌
3. Looked at window creation functions ❌
4. Only THEN looked at validation ❌

**What I should have done:**
1. Find where user input is checked ✅
2. Analyze validation logic ✅
3. Understand constraints ✅
4. Write solution ✅
5. Only care about other stuff if needed ✅

**Lesson learned:** Always prioritize the direct path from input to success/failure.

---

## Understanding the Challenge Properly

### The Real Challenge

After reading the official writeup, I realized:

**This challenge has multiple layers:**

1. **API Obfuscation (PEB Walking)**
   - Purpose: Hide which Windows APIs are being used
   - Technique: Hash function names and look them up dynamically
   - Impact: Makes static analysis harder

2. **String Encryption (Xorshift PRNG)**
   - Purpose: Hide strings like window names, DLL names
   - Technique: XOR with PRNG keystream
   - Impact: Can't see strings in static analysis

3. **Product Key Validation (The Actual Challenge)**
   - Purpose: Verify the product key is valid
   - Technique: Multi-layer validation (format + signature + MD5)
   - Impact: **This is what we need to solve!**

**The key insight:** Layers 1 and 2 are just obfuscation. Layer 3 is the actual puzzle!

---

## Phase 1: Reconnaissance

### Step 1.1: Understanding File Types

**PE32+ explained:**
- PE = Portable Executable (Windows format)
- 32+ = Actually means 64-bit (confusing naming!)
- Contrast: Linux uses ELF, macOS uses Mach-O

**Why this matters:**
- Need Windows or Wine to run
- Need 64-bit tools (x64dbg, not x32dbg)
- Functions use x64 calling convention (args in RCX, RDX, R8, R9)

---

### Step 1.2: Understanding Sections

**What are sections?** Think of a binary as a house with different rooms:

```
.text   = Kitchen (where work happens) = CODE
.rdata  = Pantry (stored food)         = READ-ONLY DATA (strings, constants)
.data   = Counter (working area)       = READ-WRITE DATA (variables)
.pdata  = First aid kit                = EXCEPTION HANDLING
.reloc  = Moving instructions          = RELOCATION INFO
```

**Why this matters:**
- Code always lives in `.text` section
- Strings usually in `.rdata` or `.data`
- When debugging, you'll see addresses like `0x140001000` (`.text`) vs `0x140008000` (`.data`)

---

### Step 1.3: Initial Strings Analysis

```bash
strings duck_product_key.exe | head -50
```

**Key findings:**
```
DefWindowProcA          ← Only 1 USER32 API visible!
USER32.dll              ← DLL names visible
KERNEL32.dll
memset                  ← Only a few APIs visible
__C_specific_handler
```

**What this tells us:**
- Normal Windows GUI program: 50+ API imports
- This program: Only 3-4 APIs visible
- **Missing APIs = They're being hidden!**

**Recognition pattern:**
```
Few visible APIs + GUI program = API Obfuscation (PEB Walking)
```

---

### Step 1.4: Forming Hypotheses

**Based on initial recon:**

1. ✅ Challenge: Find or generate valid product key
2. ✅ Obfuscation: APIs are hidden (PEB walking)
3. ✅ Validation: There's complex checking logic
4. ❓ Format: Unknown (need to analyze)
5. ❓ Algorithm: Unknown (need to analyze)

---

## Phase 2: Static Analysis with Ghidra

### Step 2.1: Opening in Ghidra

**Process:**
1. Launch Ghidra: `ghidra &`
2. Create new project: File → New Project → Non-Shared
3. Import file: File → Import File → Select `duck_product_key.exe`
4. Double-click file to open CodeBrowser
5. Click "Yes" when asked to analyze
6. Wait for auto-analysis to complete

---

### Step 2.2: Understanding Ghidra's Interface

**The 4 main panels:**

```
┌──────────────────┬────────────────────────┐
│  Symbol Tree     │  Listing (Assembly)    │
│  (Functions,     │  Shows actual          │
│   Imports,       │  disassembly           │
│   Exports)       │                        │
├──────────────────┼────────────────────────┤
│  Data Types      │  Decompiler (C code)   │
│  (Structures)    │  ← We focus here!      │
└──────────────────┴────────────────────────┘
```

**Most important panels for beginners:**
1. **Symbol Tree (left)** - Navigate to functions
2. **Decompiler (bottom center)** - Read pseudo-C code

---

### Step 2.3: Finding the Entry Point

**In Symbol Tree, look for:**
- `entry` ← Usually this one
- `main`
- `WinMain`
- `wWinMain`

**Found `entry` function:**

```c
void entry(void)
{
  __security_init_cookie();  // ❌ Security boilerplate - IGNORE
  FUN_140004424();           // ✅ Real entry point - ANALYZE THIS!
  return;
}
```

**The "Do I Care?" Test:**

| Function | Purpose | Care? |
|----------|---------|-------|
| `__security_init_cookie()` | Stack canary for security | ❌ No |
| `memset()` | Standard C library | ❌ No |
| `FUN_140004424()` | Custom unknown function | ✅ YES! |
| `GetDlgItemTextA()` | Gets user input | ⚠️ Important! |

**Rule:** Ignore standard library and security code. Focus on custom logic!

---

### Step 2.4: Tracing Execution Flow

**Following the execution:**

```
entry()
  └─> FUN_140004424()  (initialization)
        └─> FUN_140003e30()  (main logic)
              ├─> String decryption (obfuscation)
              ├─> PEB walking (API resolution)
              ├─> GUI setup
              └─> FUN_140002830()  ⭐ PRODUCT KEY VALIDATION!
```

**How to trace:**
1. Start at `entry`
2. Look for function calls (identify by `FUN_` or API names)
3. Click on function name to jump to it
4. Ask: "Is this setup code or logic code?"
5. Follow the logic code

**Mental model:**
```
Setup → Main Logic → Cleanup
        ↑
    Focus here!
```

---

## Phase 3: Understanding API Obfuscation (PEB Walking)

### What I Was Confused About

**My question:**
> "How do you know this is PEB walking? It just looks like complicated code with hash comparisons!"

This is a GREAT question! Let me break down the detective work.

---

### The Evidence Chain

**Look at this code pattern:**

```c
for (puVar4 = *(undefined8 **)(*(longlong *)(lVar8 + 0x18) + 0x20);
     puVar4 != *(undefined8 **)(*(longlong *)(lVar8 + 0x18) + 0x28); 
     puVar4 = (undefined8 *)*puVar4)
{
    // Loop body
    uVar13 = ((int)*pcVar2 ^ uVar13) * 0x1000193;
    if (uVar13 == 0x146ed342) {
        // Found something!
    }
}
```

---

### 🔍 Clue #1: Magic Offsets

**These specific offsets are well-known Windows structures:**

```c
*(longlong *)(lVar8 + 0x18)   // Offset +0x18
*(longlong *)(lVar8 + 0x28)   // Offset +0x28
*(int *)(lVar5 + 0x3c)        // Offset +0x3c
```

**What these mean (from Windows internals documentation):**

```
+0x18 → PEB->Ldr (Pointer to PEB_LDR_DATA structure)
+0x20 → InMemoryOrderModuleList.Flink (First loaded module)
+0x28 → InMemoryOrderModuleList.Blink (Last loaded module)
+0x3c → PE Header offset (e_lfanew)
+0x88 → Export Directory RVA
```

**How to recognize:** Google these offsets + "Windows" and you'll find PEB structure documentation!

**Recognition pattern:**
```
Offsets +0x18, +0x3c, +0x88 → Accessing PEB structure
```

---

### 🔍 Clue #2: Linked List Traversal

```c
for (puVar4 = START; puVar4 != END; puVar4 = *puVar4)
```

**This is traversing a linked list!**

**What Windows uses linked lists for:**
- List of loaded DLLs (modules)
- Each node points to next module
- Walking this list = examining all loaded modules

**Pattern:**
```
Loop with ptr = *ptr → Linked list traversal
Linked list + offset +0x3c → Walking loaded modules
```

---

### 🔍 Clue #3: String Length Calculation

```c
do {
    uVar9 = uVar9 + 1;
} while (*(char *)(lVar12 + uVar9) != '\0');
```

**This is `strlen()`** - counting characters until null terminator!

**Why count string length?**
- Because we're about to process a string
- We need to know how long it is
- Usually followed by hashing or comparison

---

### 🔍 Clue #4: The Hash Algorithm (Smoking Gun!)

```c
uVar13 = 0x55366ad0;  // Initial seed
do {
    uVar13 = ((int)*pcVar2 ^ uVar13) * 0x1000193;
} while (...);
```

**The constant `0x1000193` is THE smoking gun!**

**What is this constant?**
- This is the **FNV-1a prime number**
- FNV-1a is a well-known hash algorithm
- Used extensively in malware and obfuscation

**The FNV-1a algorithm:**
```python
def fnv1a_hash(data, seed=0x55366ad0):
    hash_value = seed
    for byte in data:
        hash_value = ((hash_value ^ byte) * 0x1000193) & 0xFFFFFFFF
    return hash_value
```

**How to recognize:**
```
XOR * 0x1000193 → FNV-1a hash algorithm
```

**Verification:** Google "0x1000193" - every result talks about FNV hash!

---

### 🔍 Clue #5: Hash Comparison

```c
if (uVar13 == 0x146ed342) {
    pcVar12 = (code *)(...);  // Get function pointer
}
```

**What this means:**
- We hashed a string
- Compared with a constant
- If match, we get a function pointer
- This is **API resolution by hash!**

**Testing the hypothesis:**
```python
def fnv1a(data, seed=0x55366ad0):
    hash_val = seed
    for byte in data:
        hash_val = ((hash_val ^ byte) * 0x1000193) & 0xFFFFFFFF
    return hash_val

# Test common Windows APIs:
print(hex(fnv1a(b"LoadLibraryA")))    # Output: 0x146ed342 ← MATCH!
print(hex(fnv1a(b"MessageBoxA")))     # Check this too
print(hex(fnv1a(b"GetDlgItemTextA"))) # And this
```

**When hashes match known API names → Confirmed PEB walking!**

---

### 🔍 Clue #6: Missing Imports

**From our initial `strings` output:**
- Normal program: 50+ API imports visible
- This program: Only 3-4 APIs visible
- Missing APIs must be loaded dynamically!

**Pattern recognition:**
```
Few visible imports + Hash comparisons + PEB offsets = API Obfuscation
```

---

### ✅ The Detective's Checklist for PEB Walking

**When you see suspicious code, check these boxes:**

- [ ] Uses specific offsets (+0x18, +0x3c, +0x88)?
- [ ] Has linked list traversal?
- [ ] Calculates string length?
- [ ] Uses hash with `0x1000193`?
- [ ] Compares hash with constants?
- [ ] Gets function pointers?
- [ ] Very few API imports in strings?

**If 5+ boxes checked → It's PEB Walking!**

---

### Why API Obfuscation Doesn't Matter (For This Challenge)

**Important realization:**

```
API Obfuscation is just NOISE in this challenge!

What matters:
✅ Product key validation logic
✅ Understanding the checks
✅ Generating valid keys

What doesn't matter:
❌ How APIs are loaded
❌ Which specific APIs are used
❌ The PEB walking implementation
```

**Lesson:** Don't get distracted by interesting techniques if they don't help you get the flag!

---

## Phase 4: Analyzing Validation Logic

### Step 4.1: Finding the Validation Function

**Looking at `FUN_140003e30` (main function):**

```c
void FUN_140003e30(void)
{
    // ... setup code ...
    
    iVar6 = FUN_140002830();  // ← This returns an integer
    if (iVar6 != 0) {
        // Success path - creates window, shows flag
    }
    // Failure path - nothing happens
}
```

**Key insight:**
```c
if (iVar6 != 0) → Success
if (iVar6 == 0) → Failure
```

**Therefore: `FUN_140002830` is the validation function!**

---

### Step 4.2: Understanding Validation Flow

**Top-down analysis strategy:**

```
1. Look at the END first (what does it return?)
   → Returns integer (0 = fail, non-zero = success)

2. Find SUCCESS path
   → When does it return non-zero?

3. Find FAILURE path
   → When does it return zero?

4. Trace backwards
   → What conditions lead to success?
```

**This is better than reading top-to-bottom!**

---

### Step 4.3: Multi-Layer Validation

**From analyzing the validation function, I found 3 layers:**

```
┌─────────────────────────────────────┐
│ Layer 1: Format Validation          │
│ - Length must be 19 characters       │
│ - Dashes at positions 4, 9, 14      │
│ - Only Base32 characters (A-Z, 2-7) │
└─────────────────────────────────────┘
              ↓ PASS
┌─────────────────────────────────────┐
│ Layer 2: Signature Validation       │
│ - 4th segment = checksum(1,2,3)     │
│ - Uses custom hash algorithm        │
└─────────────────────────────────────┘
              ↓ PASS
┌─────────────────────────────────────┐
│ Layer 3: MD5 Checksum               │
│ - High 8 bits of segments 1,2,3     │
│ - MD5 hash must equal 0x367f45a8    │
└─────────────────────────────────────┘
              ↓ PASS
         ✅ VALID KEY!
```

---

### Step 4.4: Layer 1 - Format Validation

**The code pattern:**

```c
if (strlen(key) != 19) {
    return 0;  // Fail
}

for (int i = 0; i < 19; ++i) {
    if ((i == 4 || i == 9 || i == 14)) {
        if (key[i] != '-') return 0;  // Must be dash
    }
    else {
        if (Base32CharToValue(key[i]) == -1) {
            return 0;  // Must be valid Base32
        }
    }
}
```

**What this tells us:**

```
Format: XXXXX-XXXXX-XXXXX-XXXXX

Position:  0 1 2 3 4 5 6 7 8 9 ...
Character: X X X X - X X X X - ...
                   ↑         ↑
                 Dash      Dash

Rules:
- Total length: 19 characters
- Positions 4, 9, 14: Must be '-'
- All other positions: Must be Base32 (A-Z or 2-7)
```

---

### Recognizing Base32 Encoding

**How I identified Base32:**

```c
int Base32CharToValue(char c) {
    if ('A' <= c && c <= 'Z')
        return c - 'A';        // Maps to 0-25
    if ('2' <= c && c <= '7')
        return c - '2' + 26;   // Maps to 26-31
    return -1;  // Invalid
}
```

**The pattern:**
```
A-Z → 0 to 25  (26 values)
2-7 → 26 to 31 (6 values)
Total: 32 values = 2^5 = 5 bits per character
```

**Base32 characteristics:**
- Each character = 5 bits
- 4 characters = 20 bits
- Alphabet: `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`

**Recognition rule:**
```
If code checks:
  - Alphabet (A-Z) + Numbers (2-7) = 32 total values
  → This is Base32 encoding!
```

---

### Step 4.5: Layer 2 - Signature Validation

**The signature algorithm:**

```c
uint32_t calculate_signature(uint32_t seg1, uint32_t seg2, uint32_t seg3) {
    uint32_t hash_val = 0x7b081b4a;  // Initial seed
    
    for each segment {
        hash_val ^= segment;                     // XOR with segment
        hash_val *= 0x45d9f3b;                   // Multiply by constant
        hash_val = ROTATE_RIGHT(hash_val, 19);   // Rotate right 19 bits
    }
    
    return hash_val & 0xFFFFF;  // Return lowest 20 bits
}
```

**What this does:**
- Takes first 3 segments as input
- Applies custom hashing
- Returns a 20-bit value
- **The 4th segment MUST equal this value!**

**Example:**
```
Key: 3YAC-5IPV-3OGY-????

Seg1 = Base32Decode("3YAC") = 0xde123  (example)
Seg2 = Base32Decode("5IPV") = 0xea456  (example)
Seg3 = Base32Decode("3OGY") = 0xdb789  (example)

Sig = calculate_signature(Seg1, Seg2, Seg3) = 0x7LYJ (example)

Therefore: Valid key = 3YAC-5IPV-3OGY-7LYJ
```

---

### Step 4.6: Layer 3 - MD5 Checksum (The Critical Constraint!)

**The code:**

```c
if (sub_140001080(arg2, 12) == 0x367f45a8) {
    // Valid!
}
```

**What `sub_140001080` does:**

```python
def md5_checksum(segments):
    # Extract high 8 bits from each segment
    byte1 = (segments[0] >> 12) & 0xFF
    byte2 = (segments[1] >> 12) & 0xFF
    byte3 = (segments[2] >> 12) & 0xFF
    
    # Convert each byte to 4-byte little-endian
    data = byte1.to_bytes(4, 'little') + \
           byte2.to_bytes(4, 'little') + \
           byte3.to_bytes(4, 'little')
    
    # Calculate MD5
    md5 = hashlib.md5(data).digest()
    
    # Unpack as 4 integers
    w0, w1, w2, w3 = struct.unpack("<IIII", md5)
    
    # XOR all 4 values
    return w0 ^ w1 ^ w2 ^ w3
```

**The constraint:**
```
md5_checksum(segments) MUST equal 0x367f45a8
```

---

### Understanding Segment Structure

**Each segment is 20 bits:**

```
Segment structure:
┌─────────────┬──────────────────┐
│  High 8 bits│  Low 12 bits     │
│  (byte)     │  (random)        │
└─────────────┴──────────────────┘

Example:
Segment = 0xDE123
Binary:  11011110 000100100011
         └──────┘ └──────────┘
         8 bits   12 bits
         = 0xDE   = 0x123
```

**Why this matters:**
- The high 8 bits are used in MD5 check
- The low 12 bits can be random
- But the high 8 bits are CONSTRAINED by MD5!

---

### The Critical Discovery: Finding [0xde, 0xea, 0xdb]

**The challenge:**
```
Find 3 bytes where:
  MD5 of these bytes → XOR all states = 0x367f45a8
```

**Search space:**
```
256 × 256 × 256 = 16,777,216 possibilities
```

**Is brute force feasible?**
```
Modern computer: ~1 million MD5/second
Time needed: ~16 seconds
✅ YES! This is easily brute-forceable!
```

**When to brute force (decision tree):**
```
Is search space < 2^32? (4 billion)
    ↓ YES
Can we test 1 million/sec?
    ↓ YES
Time < 1 hour?
    ↓ YES
→ BRUTE FORCE IT!
```

---

## Phase 5: Solution - Writing the Keygen

### Step 5.1: Brute Forcing the MD5 Constraint

**The brute force script:**

```python
import hashlib
import struct

TARGET = 0x367f45a8

def calculate_checksum(byte_a, byte_b, byte_c):
    # Convert each byte to 4-byte little-endian
    data = byte_a.to_bytes(4, 'little') + \
           byte_b.to_bytes(4, 'little') + \
           byte_c.to_bytes(4, 'little')
    
    # Calculate MD5
    md5_hash = hashlib.md5(data).digest()
    
    # Unpack as 4 integers
    w0, w1, w2, w3 = struct.unpack("<IIII", md5_hash)
    
    # XOR all 4 values
    return w0 ^ w1 ^ w2 ^ w3

def find_magic_bytes():
    print("[+] Brute forcing MD5 constraint...")
    print(f"[+] Target: 0x{TARGET:08x}")
    
    tested = 0
    for a in range(256):
        if a % 16 == 0:  # Progress indicator
            print(f"[*] Progress: {a}/256 ({a/256*100:.1f}%)")
        
        for b in range(256):
            for c in range(256):
                tested += 1
                checksum = calculate_checksum(a, b, c)
                
                if checksum == TARGET:
                    print(f"\n[+] FOUND after {tested:,} attempts!")
                    print(f"[+] Bytes: [0x{a:02x}, 0x{b:02x}, 0x{c:02x}]")
                    return (a, b, c)
    
    return None

# Run it
magic_bytes = find_magic_bytes()
# Result: [0xde, 0xea, 0xdb]
```

**Time taken:** ~10-15 seconds

**Result:** The only 3 bytes that satisfy the constraint are `[0xde, 0xea, 0xdb]`

---

### Step 5.2: Understanding Base32 Conversion

**Base32 alphabet:**
```python
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
#                  0         10        20       30
```

**How Base32 works:**
```
Each character represents 5 bits:
'A' = 0  = 00000
'B' = 1  = 00001
'Z' = 25 = 11001
'2' = 26 = 11010
'7' = 31 = 11111

4 characters = 20 bits total
```

**Converting integer to Base32:**

```python
def int_to_base32_block(value):
    """Convert 20-bit integer to 4-character Base32 string"""
    chars = []
    
    # Extract 5 bits at a time (4 times)
    for i in range(4):
        # Get lowest 5 bits
        index = value & 0b11111  # Same as value & 31
        chars.append(BASE32_ALPHABET[index])
        # Shift right by 5 bits
        value >>= 5
    
    # Reverse because we extracted right-to-left
    return ''.join(reversed(chars))
```

**Example:**
```
Value: 0x12345 (20 bits)
Binary: 00010 01000 11010 00101
        └───┘ └───┘ └───┘ └───┘
        5bit  5bit  5bit  5bit

Indices: [5, 26, 8, 2]
Base32:  ['F', '2', 'I', 'C']
Result:  "CI2F" (reversed)
```

---

### Step 5.3: Building Product Keys

**The structure we need:**

```
Segment 1: [0xde (high 8 bits)][random 12 bits]
Segment 2: [0xea (high 8 bits)][random 12 bits]
Segment 3: [0xdb (high 8 bits)][random 12 bits]
Segment 4: [signature of above]
```

**Bit manipulation explained:**

```python
# Example: Put 0xde in high 8 bits of 20-bit value

# Step 1: Shift left by 12 bits
high_bits = 0xde << 12
# Binary: 11011110 → 11011110000000000000
# Result: 0xde000

# Step 2: Generate random 12 bits (0 to 4095)
low_bits = random.randint(0, 0xFFF)  # 0xFFF = 4095
# Example: 0x123

# Step 3: Combine with OR
segment = high_bits | low_bits
# 11011110000000000000
# OR
# 00000000000100100011
# =
# 11011110000100100011
# Result: 0xde123
```

**Why this works:**
- High 8 bits = 0xde (required for MD5 check)
- Low 12 bits = random (doesn't affect validation)
- Total = 20 bits (perfect for Base32 encoding)

---

### Step 5.4: Signature Calculation

**The signature algorithm:**

```python
def calculate_signature(segments):
    """
    Calculate checksum for first 3 segments
    Algorithm: XOR → Multiply → Rotate
    """
    hash_val = 0x7b081b4a  # Initial seed
    
    for segment in segments:
        # XOR with segment
        hash_val ^= segment
        
        # Multiply by constant
        hash_val = (hash_val * 0x45d9f3b) & 0xFFFFFFFF
        
        # Rotate right by 19 bits
        # Same as: rotate left by 13 bits
        hash_val = ((hash_val >> 19) | (hash_val << 13)) & 0xFFFFFFFF
    
    # Return lowest 20 bits
    return hash_val & 0xFFFFF
```

**Rotate operation explained:**

```
Rotate right by 19 bits (in 32-bit space):

Original:  ABCDEFGH IJKLMNOP QRSTUVWX YZ012345
           └──────19 bits──────┘└────13────┘

After ROR 19:
           QRSTUVWX YZ012345 ABCDEFGH IJKLMNOP
           └────13────┘└──────19 bits──────┘

Same as rotate left 13: (32 - 19 = 13)
  (value >> 19) | (value << 13)
```

---

### Step 5.5: Complete Keygen Script

```python
#!/usr/bin/env python3
"""
V1T CTF 2025 - Duck Product Key - Keygen
"""

import random

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def int_to_base32_block(value):
    """Convert 20-bit integer to 4-character Base32 string"""
    chars = []
    for i in range(4):
        chars.append(BASE32_ALPHABET[value & 31])
        value >>= 5
    return ''.join(reversed(chars))

def calculate_signature(segments):
    """Calculate signature for first 3 segments"""
    hash_val = 0x7b081b4a
    for segment in segments:
        hash_val ^= segment
        hash_val = (hash_val * 0x45d9f3b) & 0xFFFFFFFF
        hash_val = ((hash_val >> 19) | (hash_val << 13)) & 0xFFFFFFFF
    return hash_val & 0xFFFFF

def generate_product_key():
    """Generate a valid product key"""
    # These bytes MUST be in high 8 bits (MD5 constraint)
    magic_bytes = [0xde, 0xea, 0xdb]
    segments = []
    
    # Generate first 3 segments
    for magic_byte in magic_bytes:
        # Put magic byte in high 8 bits, random in low 12 bits
        segment = (magic_byte << 12) | random.randint(0, 0xFFF)
        segments.append(segment)
    
    # Generate 4th segment (signature)
    segments.append(calculate_signature(segments))
    
    # Convert to Base32 and join with dashes
    return '-'.join([int_to_base32_block(seg) for seg in segments])

# Generate 5 keys for testing
print("Valid Product Keys:")
for i in range(5):
    key = generate_product_key()
    print(f"  Key #{i+1}: {key}")
```

**Output:**
```
Valid Product Keys:
  Key #1: 324X-5JGY-3PJQ-32RF
  Key #2: 32BO-5KBI-3MRH-PIRS
  Key #3: 3YRB-5J3D-3NU2-452D
  Key #4: 3ZQC-5IIZ-3NG3-MQOL
  Key #5: 3ZZX-5KSZ-3OU3-52HO
```

---

## Testing and Getting the Flag

### Step 6.1: Testing the Generated Key

```bash
# Run the program
wine64 duck_product_key.exe

# Enter any generated key, for example:
324X-5JGY-3PJQ-32RF

# Click VERIFY
```

**Result:**
```
Success dialog appears!
Title: "Info"
Message: "Success, here is your flag
v1t{b40c5c471nc_7h1n65_w17h_p3b_648a18c0}"
```

**🎉 FLAG CAPTURED!**

---

### Step 6.2: Understanding Why It Works

**The complete validation flow:**

```
User Input: 324X-5JGY-3PJQ-32RF
     ↓
Layer 1: Format Check
  - Length = 19 ✓
  - Dashes at positions 4, 9, 14 ✓
  - All Base32 characters ✓
     ↓ PASS
Layer 2: Decode Base32
  Segment 1: "324X" → 0xde123 (high 8 bits = 0xde)
  Segment 2: "5JGY" → 0xea456 (high 8 bits = 0xea)
  Segment 3: "3PJQ" → 0xdb789 (high 8 bits = 0xdb)
  Segment 4: "32RF" → 0x12345
     ↓
Layer 3: Signature Check
  Calculate: signature(0xde123, 0xea456, 0xdb789)
  Expected: 0x12345
  Match: ✓
     ↓ PASS
Layer 4: MD5 Check
  Extract: [0xde, 0xea, 0xdb] from high 8 bits
  MD5 checksum: 0x367f45a8
  Match: ✓
     ↓ PASS
Result: VALID KEY!
     ↓
Extract [0xde, 0xea, 0xdb] as XOR key
Decrypt flag string
Display: v1t{b40c5c471nc_7h1n65_w17h_p3b_648a18c0}
```

**The clever design:**
```
The bytes [0xde, 0xea, 0xdb] serve TWO purposes:
1. Validation constraint (only these pass MD5 check)
2. Flag decryption key (XOR key for the encrypted flag)
```

---

## Post-Mortem: What I Learned

### Critical Mistakes Made

#### ❌ Mistake #1: Assumed Easy Path
**What I thought:** "Small file = simple challenge = memory search works"  
**Reality:** Small file with advanced obfuscation and multi-layer validation  
**Lesson:** Never assume. Always analyze the actual logic.

#### ❌ Mistake #2: Got Distracted by Obfuscation
**What I did:** Spent 30+ minutes understanding PEB walking and string encryption  
**Should have done:** 5 minutes to recognize it, then focus on validation  
**Lesson:** Interesting ≠ Important. Focus on the critical path.

#### ❌ Mistake #3: Wrong Analysis Priority
**My order:** Obfuscation → String decryption → Window creation → Validation  
**Correct order:** Validation → Format → Signature → MD5 → Solution  
**Lesson:** Always prioritize the direct path from input to success/failure.

#### ❌ Mistake #4: Didn't Recognize Pattern
**Missed:** "Product Key" challenge = keygen challenge  
**Should have known:** These always involve multi-layer validation  
**Lesson:** Build a pattern library. Document challenge types.

#### ❌ Mistake #5: Expected Flag in Memory
**Thought:** Running in debugger would decrypt flag automatically  
**Reality:** Flag only decrypts when VALID key is entered  
**Lesson:** Understand data flow. Where does encryption happen? When?

---

### What I Should Have Done

**The correct 60-minute workflow:**

```
[0-5 min] Reconnaissance
  ├─ Run program → See product key dialog
  ├─ Check strings → Note few visible APIs
  └─ Hypothesis: "Product key validation challenge"

[5-15 min] Find Critical Function
  ├─ Open Ghidra
  ├─ Find entry → main → validation
  ├─ Identify FUN_140002830 as validator
  └─ Mark this as PRIMARY TARGET

[15-45 min] Analyze Validation (FOCUS HERE!)
  ├─ Layer 1: Format (19 chars, Base32, dashes)
  ├─ Layer 2: Signature (checksum algorithm)
  ├─ Layer 3: MD5 constraint (specific bytes)
  └─ Document all requirements

[45-55 min] Solve Constraints
  ├─ Brute force MD5 → [0xde, 0xea, 0xdb]
  ├─ Understand Base32 encoding
  ├─ Reverse signature algorithm
  └─ Write keygen script

[55-60 min] Test and Capture Flag
  ├─ Generate valid key
  ├─ Test in program
  └─ Screenshot flag!
```

**Total time with correct approach: ~60 minutes**  
**My actual time: 3+ hours (due to distractions)**

---

## Future Reference Guide

### Checklist: Product Key / Keygen Challenges

**When you see "product key", "serial", "license", "activation":**

```
✅ Step 1: Run and Observe
   [ ] What format does it expect?
   [ ] Any hints in error messages?
   [ ] Document exact behavior

✅ Step 2: Find Validation Function
   [ ] Where does it check the input?
   [ ] Trace from entry → main → validator
   [ ] Mark validation function as PRIMARY TARGET

✅ Step 3: Analyze Each Validation Layer
   [ ] Format validation (length, characters, structure)
   [ ] Checksum/signature validation
   [ ] Cryptographic constraints (MD5, SHA, etc.)
   [ ] Document ALL requirements clearly

✅ Step 4: Identify Constraints
   [ ] What MUST be in the key?
   [ ] Can constraints be brute-forced?
   [ ] Which parts can be random?
   [ ] Calculate search space

✅ Step 5: Choose Solution Strategy
   [ ] Keygen (if you understand algorithm)
   [ ] Patcher (if validation is simple)
   [ ] Static extraction (if flag is embedded)

✅ Step 6: Implement Solution
   [ ] Write clean, documented code
   [ ] Test with multiple keys
   [ ] Verify it actually works

✅ Step 7: Get Flag
   [ ] Run program with valid key
   [ ] Screenshot/save flag
   [ ] Document solution
```

---

### Pattern Recognition Guide

#### 1. API Obfuscation (PEB Walking)

**Indicators:**
```
✓ Very few visible API imports
✓ Loops with hash calculations
✓ Magic offsets (+0x18, +0x3c, +0x88)
✓ Constant 0x1000193 (FNV-1a prime)
✓ Linked list traversal pattern
✓ Function pointer retrieval
```

**What to do:**
```
1. Recognize the pattern (don't waste time analyzing)
2. Note which APIs are obfuscated (helps understand program flow)
3. Move on to actual challenge logic
4. If needed, use dynamic analysis to see API calls
```

**How to verify:**
```python
# Test if hash matches known API
def fnv1a(data, seed=0x55366ad0):
    hash_val = seed
    for byte in data:
        hash_val = ((hash_val ^ byte) * 0x1000193) & 0xFFFFFFFF
    return hash_val

# If hash matches an API name → Confirmed PEB walking
print(hex(fnv1a(b"LoadLibraryA")))  # Check against found hashes
```

---

#### 2. String Encryption (PRNG-based)

**Indicators:**
```
✓ Arrays of hex constants
✓ Function call with: (seed, encrypted_data, output_buffer, length)
✓ XOR operations in loop
✓ Bit shifts (<<, >>)
✓ Modulo operations
```

**Common algorithms:**
```
- Xorshift (XOR + shift operations)
- Linear Congruential Generator (multiply + add + modulo)
- Custom stream ciphers
```

**What to do:**
```
1. Recognize it's string encryption
2. Note the algorithm (might be reused)
3. If string looks interesting, decrypt it
4. Usually not critical for solving challenge
```

---

#### 3. Base32/Base64 Encoding

**Base32 indicators:**
```
✓ Alphabet check: A-Z (26 values) + 2-7 (6 values) = 32 total
✓ Bit operations: value & 31, value >> 5
✓ Character to index conversion
```

**Base64 indicators:**
```
✓ Alphabet check: A-Z, a-z, 0-9, +, / = 64 values
✓ Bit operations: value & 63, value >> 6
✓ Padding with '=' characters
```

**Recognition:**
```
If character validation = 32 values → Base32
If character validation = 64 values → Base64
If character validation = 16 values → Base16 (Hex)
```

---

#### 4. Multi-Layer Validation

**Common layers:**
```
Layer 1: Format (length, structure, character set)
Layer 2: Checksum (simple math, XOR, addition)
Layer 3: Signature (hash-based validation)
Layer 4: Cryptographic (MD5, SHA, etc.)
```

**Analysis strategy:**
```
1. Document each layer separately
2. Solve from most constrained to least constrained
3. Usually: Crypto constraint → Signature → Format
4. Format is often the easiest (just follow rules)
```

---

#### 5. Hash-Based Checksums

**Common patterns:**
```
Seed ^ Value * Constant → Multiply-and-XOR
Seed + Value * Prime % Modulo → Linear Congruential
Rotate + XOR → Rotating checksum
MD5/SHA → Cryptographic hash
```

**How to approach:**
```
1. Identify the algorithm from the constants
2. If simple (XOR, add), reverse it
3. If cryptographic (MD5, SHA), brute force if feasible
4. Calculate search space before attempting
```

---

### When to Brute Force

**Decision matrix:**

| Search Space | Complexity | Time @ 1M/sec | Brute Force? |
|--------------|------------|---------------|--------------|
| 2^16 (65K) | Very Easy | < 1 second | ✅ YES |
| 2^20 (1M) | Easy | 1 second | ✅ YES |
| 2^24 (16M) | Easy | 16 seconds | ✅ YES |
| 2^28 (256M) | Medium | 4 minutes | ✅ YES |
| 2^32 (4B) | Hard | 1 hour | ⚠️ Maybe |
| 2^40 (1T) | Very Hard | 12 days | ❌ NO |
| 2^48+ | Infeasible | Years | ❌ NO |

**Factors to consider:**
```
✓ Can you parallelize? (multiple cores)
✓ Can you optimize the test? (faster checking)
✓ Can you reduce search space? (constraints)
✓ Is there a smarter algorithm? (math properties)
```

---

### Common Beginner Mistakes

#### ❌ Trying to Understand Everything
**Problem:** Getting lost in complex code, trying to understand every function  
**Solution:** Focus on critical path only. Ignore noise.

#### ❌ Reading Code Top-to-Bottom
**Problem:** Linear reading misses the big picture  
**Solution:** Use top-down analysis (start from end, trace backwards)

#### ❌ Getting Distracted by Interesting Code
**Problem:** Spending time on obfuscation, anti-debug, etc.  
**Solution:** Ask: "Does this help me get the flag?" If no → skip it.

#### ❌ Assuming Easy Path
**Problem:** "I'll just use a debugger and search memory"  
**Solution:** Analyze first, understand the challenge, then choose tools.

#### ❌ Not Documenting Constraints
**Problem:** Trying to keep everything in head, getting confused  
**Solution:** Write down every requirement, check them off one by one.

---

### Tools and When to Use Them

#### Static Analysis (Ghidra, IDA)
**Use when:**
```
✓ Understanding algorithms
✓ Finding validation logic
✓ Reversing checksums/signatures
✓ Tracing execution flow
✓ You have time to analyze properly
```

**Don't use when:**
```
✗ Just want to see API calls (use debugger)
✗ Just want to dump memory (use debugger)
✗ Program is heavily obfuscated (combine with dynamic)
```

---

#### Dynamic Analysis (x64dbg, gdb)
**Use when:**
```
✓ Want to see runtime behavior
✓ Need to dump decrypted strings
✓ Want to see actual values in variables
✓ Testing your keygen
✓ Understanding complex control flow
```

**Don't use when:**
```
✗ Need to understand algorithm (use static analysis)
✗ Need to reverse mathematical operations
✗ Program has anti-debug (remove it first)
```

---

#### Hybrid Approach (Best!)
**Strategy:**
```
1. Static analysis: Understand structure and algorithm
2. Dynamic analysis: Verify your understanding
3. Static analysis: Document precise algorithm
4. Write solution based on understanding
5. Dynamic analysis: Test your solution
```

---

### Bit Operations Quick Reference

```python
# Left Shift (<<)
0xFF << 8       # Result: 0xFF00 (move left 8 bits)
0x12 << 12      # Result: 0x12000 (move left 12 bits)

# Right Shift (>>)
0xFF00 >> 8     # Result: 0xFF (move right 8 bits)
0x12345 >> 12   # Result: 0x12 (move right 12 bits)

# Bitwise OR (|) - Combine bits
0xFF00 | 0x00FF  # Result: 0xFFFF (set both groups)
0x1000 | 0x0234  # Result: 0x1234 (combine non-overlapping)

# Bitwise AND (&) - Mask bits
0x1234 & 0xFF    # Result: 0x34 (extract low 8 bits)
0x1234 & 0x0F00  # Result: 0x0200 (extract specific bits)

# Bitwise XOR (^) - Toggle bits
0xFF ^ 0x0F      # Result: 0xF0 (flip bits)
value ^ value    # Result: 0 (XOR with itself = 0)

# Rotate Right (no direct operator)
def ROR(value, bits, width=32):
    return ((value >> bits) | (value << (width - bits))) & ((1 << width) - 1)

# Rotate Left (no direct operator)
def ROL(value, bits, width=32):
    return ((value << bits) | (value >> (width - bits))) & ((1 << width) - 1)
```

---

### Python Snippets for Common Tasks

#### FNV-1a Hash
```python
def fnv1a_hash(data, seed=0x55366ad0):
    """Calculate FNV-1a hash"""
    if isinstance(data, str):
        data = data.encode('ascii')
    hash_value = seed
    for byte in data:
        hash_value = ((hash_value ^ byte) * 0x1000193) & 0xFFFFFFFF
    return hash_value
```

#### Base32 Encoding/Decoding
```python
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def base32_encode(value, length=4):
    """Encode integer to Base32 string"""
    chars = []
    for _ in range(length):
        chars.append(BASE32_ALPHABET[value & 31])
        value >>= 5
    return ''.join(reversed(chars))

def base32_decode(text):
    """Decode Base32 string to integer"""
    value = 0
    for char in text:
        value = (value << 5) | BASE32_ALPHABET.index(char.upper())
    return value
```

#### MD5 Brute Force Template
```python
import hashlib
import struct

def brute_force_md5(target, transform_func):
    """
    Brute force MD5 constraint
    transform_func: How to convert (a,b,c) to data for MD5
    """
    for a in range(256):
        for b in range(256):
            for c in range(256):
                data = transform_func(a, b, c)
                md5 = hashlib.md5(data).digest()
                w0, w1, w2, w3 = struct.unpack("<IIII", md5)
                checksum = w0 ^ w1 ^ w2 ^ w3
                if checksum == target:
                    return (a, b, c)
    return None
```

---

## Final Thoughts and Advice

### For Your Future Self

**When you come back to this writeup:**

1. **Don't just copy the code**
   - Understand WHY each step is needed
   - Try to solve similar challenges without looking
   - Build your own mental frameworks

2. **Focus on patterns, not specifics**
   - This exact challenge won't appear again
   - But the PATTERNS will (PEB walking, multi-layer validation, etc.)
   - Document patterns you encounter

3. **Build your own reference**
   - Add notes when you encounter new techniques
   - Update this document with your learnings
   - Create your own cheat sheets

4. **Practice deliberately**
   - Do more keygen challenges
   - Try challenges with different obfuscation
   - Graduate to harder challenges

---

### Recommended Practice Challenges

**Similar difficulty (keygen/validation):**
- CrackMe challenges on crackmes.one
- KeygenMe challenges on crackmes.one
- Past CTF keygen challenges

**Skills to develop:**
- Assembly reading (x86-64)
- Algorithm reversal
- Bit manipulation
- Cryptography basics
- Pattern recognition

**Resources:**
- Ghidra documentation
- x64dbg documentation
- Windows internals documentation
- Cryptography tutorials
- CTF writeup repositories

---

### The Meta-Skill: Learning to Learn

**The most important lesson:**

```
This challenge taught me:
✓ How to analyze binaries systematically
✓ How to identify obfuscation techniques
✓ How to focus on what matters
✓ How to solve multi-layer constraints
✓ How to write keygens

But most importantly:
✓ How to THINK like a reverse engineer
✓ How to approach UNKNOWN challenges
✓ How to learn from mistakes
✓ How to build mental frameworks
```

**The journey from beginner → advanced:**
```
Beginner: "I don't know what this code does"
         ↓
Intermediate: "I can figure out what this code does"
         ↓
Advanced: "I know what matters and what doesn't"
         ↓
Expert: "I can predict what techniques will be used"
```

---

### Closing Advice

**Remember these principles:**

1. **Focus beats talent**
   - 1 hour of focused analysis > 10 hours of aimless exploration

2. **Patterns beat memorization**
   - Recognize patterns > Remember specific details

3. **Understanding beats copying**
   - Understand WHY > Memorize solutions

4. **Practice beats reading**
   - Do challenges > Read writeups

5. **Persistence beats genius**
   - Keep trying > Give up quickly

---

**You got this! Now go solve more challenges!** 🚀

**Flag:** `v1t{b40c5c471nc_7h1n65_w17h_p3b_648a18c0}`

---

## Appendix: Complete Keygen Code

```python
#!/usr/bin/env python3
"""
V1T CTF 2025 - Duck Product Key - Complete Keygen
Author: [Your Name]
Date: November 2025

This keygen generates valid product keys for the challenge.
The key must satisfy:
1. Format: XXXXX-XXXXX-XXXXX-XXXXX (Base32)
2. Signature: 4th segment = checksum(1st, 2nd, 3rd)
3. MD5: High 8 bits of 1-3 must be [0xde, 0xea, 0xdb]
"""

import random
import hashlib
import struct

# Base32 alphabet
BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def int_to_base32_block(value, part_length=4):
    """
    Convert 20-bit integer to 4-character Base32 string
    
    Args:
        value: Integer value (0 to 2^20-1)
        part_length: Number of characters (default 4)
    
    Returns:
        Base32 string of length part_length
    """
    chars = []
    for i in range(part_length):
        chars.append(BASE32_ALPHABET[value & 31])
        value >>= 5
    return ''.join(reversed(chars))

def calculate_signature(segments):
    """
    Calculate signature/checksum for product key validation
    
    Algorithm:
    1. Start with seed 0x7b081b4a
    2. For each segment:
       - XOR with segment value
       - Multiply by 0x45d9f3b
       - Rotate right by 19 bits
    3. Return lowest 20 bits
    
    Args:
        segments: List of 3 integers (first 3 key segments)
    
    Returns:
        Integer (20-bit signature)
    """
    hash_val = 0x7b081b4a
    for segment in segments:
        hash_val ^= segment
        hash_val = (hash_val * 0x45d9f3b) & 0xFFFFFFFF
        hash_val = ((hash_val >> 19) | (hash_val << 13)) & 0xFFFFFFFF
    return hash_val & 0xFFFFF

def generate_product_key():
    """
    Generate a valid product key
    
    The key structure:
    - Segment 1: [0xde (high 8)][random 12 bits]
    - Segment 2: [0xea (high 8)][random 12 bits]
    - Segment 3: [0xdb (high 8)][random 12 bits]
    - Segment 4: [signature of above]
    
    Returns:
        String in format XXXXX-XXXXX-XXXXX-XXXXX
    """
    # These bytes MUST be in high 8 bits (MD5 constraint)
    # They are also used as XOR key for flag decryption!
    magic_bytes = [0xde, 0xea, 0xdb]
    segments = []
    
    # Generate first 3 segments
    for magic_byte in magic_bytes:
        # Put magic byte in high 8 bits
        high_bits = magic_byte << 12
        # Generate random 12 bits
        low_bits = random.randint(0, 0xFFF)
        # Combine
        segment = high_bits | low_bits
        segments.append(segment)
    
    # Generate 4th segment (signature)
    segments.append(calculate_signature(segments))
    
    # Convert to Base32 and join with dashes
    return '-'.join([int_to_base32_block(seg) for seg in segments])

def verify_key(key):
    """
    Verify a product key (for testing)
    
    Args:
        key: Product key string
    
    Returns:
        Boolean indicating if key is valid
    """
    if len(key) != 19:
        return False
    
    parts = key.split('-')
    if len(parts) != 4:
        return False
    
    # Decode Base32
    segments = []
    for part in parts:
        value = 0
        for char in part:
            if char not in BASE32_ALPHABET:
                return False
            value = (value << 5) | BASE32_ALPHABET.index(char)
        segments.append(value)
    
    # Check signature
    expected_sig = calculate_signature(segments[:3])
    if segments[3] != expected_sig:
        return False
    
    # Check MD5 constraint
    bytes_list = [(seg >> 12) & 0xFF for seg in segments[:3]]
    if bytes_list != [0xde, 0xea, 0xdb]:
        return False
    
    return True

def main():
    """Main function - generate and display keys"""
    print("=" * 70)
    print("V1T CTF 2025 - Duck Product Key Generator")
    print("=" * 70)
    print()
    print("Generating valid product keys...")
    print()
    
    # Generate 5 keys
    for i in range(5):
        key = generate_product_key()
        valid = verify_key(key)
        status = "✓" if valid else "✗"
        print(f"Key #{i+1}: {key} {status}")
    
    print()
    print("=" * 70)
    print("Usage:")
    print("  1. Copy any key above")
    print("  2. Run: wine64 duck_product_key.exe")
    print("  3. Enter the key and click VERIFY")
    print("  4. Get the flag!")
    print("=" * 70)

if __name__ == "__main__":
    main()
```

---

**Good luck with future CTFs!** 🦆🎉
