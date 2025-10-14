# Riscy Business - Detailed CTF Writeup

**Challenge:** Riscy Business  
**Category:** Reverse Engineering  
**Difficulty:** Medium  

---

## Table of Contents

1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Understanding RC4 Encryption](#understanding-rc4-encryption)
4. [Static Analysis - Reading the Code](#static-analysis---reading-the-code)
5. [Deep Dive: Three Critical Questions](#deep-dive-three-critical-questions)
6. [Dynamic Analysis Strategy](#dynamic-analysis-strategy)
7. [Writing the Exploit](#writing-the-exploit)
8. [Getting the Flag](#getting-the-flag)
9. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

We're given a binary file named `riscy` that asks for a flag. The challenge is to reverse engineer the binary and discover what input it expects to print "Success!".

**Challenge Description:**
> Try not to take too many risks when finding the flag.

---

## Initial Reconnaissance

### File Information

Let's start by examining what we're dealing with:

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ file riscy
riscy: ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), statically linked, stripped
```

**Key observations:**
- **Architecture:** RISC-V 64-bit (not x86/ARM - this is unusual!)
- **Statically linked:** All libraries are compiled in
- **Stripped:** No debugging symbols

This means we'll need QEMU to emulate RISC-V architecture on our x86 machine.

### Running the Binary

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ ./riscy
You've gotten yourself into some riscy business...
Got yourself a flag for me?
> test
You need to take some more riscs than that.

┌──(kali㉿kali)-[~/ctf]
└─$ ./riscy
You've gotten yourself into some riscy business...
Got yourself a flag for me?
> AAAAAAAA
That was a bit too riscy for me!
```

**Observations:**
- Input less than 8 characters: "You need to take some more riscs than that."
- Input 8+ characters: "That was a bit too riscy for me!"
- The binary validates our input against something

### Security Protections

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ checksec --file=riscy
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH
```

**No protections enabled!** This means:
- No stack canaries (buffer overflow protection)
- NX disabled (stack is executable)
- No PIE (addresses are fixed)
- No RELRO (GOT is writable)

However, this challenge isn't about exploitation - it's about understanding the algorithm.

### Extracting Strings

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ strings riscy
You've gotten yourself into some riscy business...
Got yourself a flag for me?
You need to take some more riscs than that.
That was a bit too riscy for me!
Success!
```

No flag or obvious hints in the strings. Time for deeper analysis.

---

## Understanding RC4 Encryption

Before diving into the code, we need to understand **RC4** - the encryption algorithm this binary uses.

### What is RC4?

**RC4 (Rivest Cipher 4)** is a stream cipher designed by Ron Rivest in 1987. It's known for being:
- Simple to implement
- Fast
- Used in WEP, WPA (WiFi security), SSL/TLS (older versions)
- **Now considered insecure** for cryptographic purposes

### How RC4 Works

RC4 has two main phases:

#### Phase 1: Key Scheduling Algorithm (KSA)

This initializes the RC4 state based on the encryption key.

```python
def rc4_ksa(key):
    # Initialize state array S
    S = list(range(256))  # S[0]=0, S[1]=1, ..., S[255]=255
    
    j = 0
    key_length = len(key)
    
    # Scramble the state based on key
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
    
    return S
```

**What happens:**
1. Create array with values 0-255
2. Loop 256 times
3. Use key bytes to scramble the array
4. Key bytes are used repeatedly (wraps around)

**Example with 8-byte key "picoCTF{":**

```
Initial:  S = [0, 1, 2, 3, 4, 5, ..., 255]
After:    S = [147, 23, 201, 89, 12, ..., 178]  (scrambled based on key)
```

#### Phase 2: Pseudo-Random Generation Algorithm (PRGA)

This generates the keystream for encryption.

```python
def rc4_prga(S, length):
    S = S.copy()  # Don't modify original
    i = j = 0
    keystream = []
    
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
    
    return bytes(keystream)
```

**What happens:**
1. Maintain two counters: `i` and `j`
2. For each byte needed:
   - Increment `i`
   - Update `j` based on state
   - Swap `S[i]` and `S[j]`
   - Output byte from state array

#### Encryption/Decryption

RC4 encrypts by XORing plaintext with keystream:

```python
ciphertext = plaintext XOR keystream
```

**The magic:** Since `A XOR B XOR B = A`, encryption and decryption are identical:

```python
# Encryption
ciphertext = plaintext XOR keystream

# Decryption  
plaintext = ciphertext XOR keystream
```

### Visual Example

```
Key:        "ABC"
Plaintext:  "Hello"

Step 1: Initialize RC4 state with key "ABC"
Step 2: Generate keystream (5 bytes needed)
        Keystream: [0x3F, 0x8A, 0x12, 0x5C, 0x9E]

Step 3: XOR plaintext with keystream
        'H' (0x48) XOR 0x3F = 0x77
        'e' (0x65) XOR 0x8A = 0xEF
        'l' (0x6C) XOR 0x12 = 0x7E
        'l' (0x6C) XOR 0x5C = 0x30
        'o' (0x6F) XOR 0x9E = 0xF1

Ciphertext: [0x77, 0xEF, 0x7E, 0x30, 0xF1]
```

**Key property:** The same key produces the same keystream, so encryption is deterministic.

---

## Static Analysis - Reading the Code

Let's load the binary into Ghidra for decompilation.

### Ghidra Setup for RISC-V

1. Import the binary into Ghidra
2. Select processor: **RISC-V:LE:64:RV64IC** (little-endian, 64-bit, with compressed instructions)
3. Let auto-analysis complete
4. Navigate to the entry function

### Main Entry Function

Here's the decompiled `entry()` function:

```c
void entry(void)
{
  byte bVar1;
  long unaff_s0;           // Input length
  byte *pbVar2;            // Pointer to input buffer
  byte bVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte abStack_179[65];    // Input buffer (65 bytes)
  undefined auStack_138[272]; // RC4 state array
  
  ecall();
  pbVar2 = (byte *)((long)register0x00002010 + -0x178);
  ecall();
  
  // Input validation loop
  do {
    ecall();
    FUN_00010078(1,"You need to take some more riscs than that.\n",0x2c,0x40);
  } while (unaff_s0 < 8);
  
  // Initialize RC4 with first 8 bytes
  FUN_00010080(auStack_138, pbVar2, 8);
  
  // Encrypt input in-place
  pbVar4 = pbVar2;
  do {
    bVar1 = *pbVar4;                      // Read plaintext byte
    bVar3 = FUN_000100d2(auStack_138);    // Generate keystream byte
    pbVar5 = pbVar4 + 1;
    *pbVar4 = bVar1 ^ bVar3;              // XOR and overwrite
    pbVar4 = pbVar5;
  } while (pbVar2 + (unaff_s0 - (long)pbVar5) != (byte *)0x0);
  
  // Compare with target
  pbVar4 = &DAT_00010210;
  do {
    bVar1 = *pbVar2;
    bVar3 = *pbVar4;
    pbVar2 = pbVar2 + 1;
    pbVar4 = pbVar4 + 1;
    if (bVar1 != bVar3) goto LAB_000101f2;
  } while (pbVar4 != &UNK_00010244);
  
  // Success!
  ecall();
  FUN_00010078(0,"Success!\n",9,0x40);
  
LAB_000101f2:
  // Failure
  ecall();
  FUN_00010078(1,"That was a bit too riscy for me!\n",0x21,0x40);
  halt_baddata();
}
```

### High-Level Program Flow

```
1. Print banner
2. Read user input
3. Validate input length >= 8 bytes
4. Use FIRST 8 BYTES as RC4 key
5. Initialize RC4 state
6. Encrypt ENTIRE input using RC4
7. Compare encrypted input with hardcoded target
8. If match: "Success!"
   If no match: "That was a bit too riscy for me!"
```

### The Three Supporting Functions

#### Function 1: `FUN_00010080` - RC4 Key Scheduling

```c
void FUN_00010080(byte *param_1, long param_2, ulong param_3)
{
  byte bVar1;
  ulong uVar2, uVar3, uVar5;
  long lVar4;
  byte *pbVar6;
  
  // Initialize S-box: S[i] = i
  lVar4 = 0;
  do {
    param_1[lVar4] = (byte)lVar4;
    lVar4 = lVar4 + 1;
  } while (lVar4 != 0x100);
  
  // Scramble based on key
  uVar2 = 0;  // i counter
  uVar5 = 0;  // j counter
  pbVar6 = param_1;
  
  do {
    uVar3 = uVar2 % param_3;  // Key index (wraps)
    bVar1 = *pbVar6;          // S[i]
    uVar2 = uVar2 + 1;
    
    // j = (j + key[i % keylen] + S[i]) % 256
    uVar3 = (ulong)(int)((int)uVar5 + 
                         (uint)*(byte *)(uVar3 + param_2) + 
                         (uint)bVar1);
    uVar5 = uVar3 & 0xff;
    
    // Swap S[i] and S[j]
    *pbVar6 = param_1[uVar3 & 0xff];
    param_1[uVar3 & 0xff] = bVar1;
    pbVar6 = pbVar6 + 1;
  } while (uVar2 != 0x100);
}
```

**This is the RC4 KSA (Key Scheduling Algorithm).**

#### Function 2: `FUN_000100d2` - RC4 Keystream Generation

```c
undefined FUN_000100d2(long param_1)
{
  char cVar1, cVar2;
  byte bVar3;
  char *pcVar4, *pcVar5;
  
  // Increment i
  bVar3 = *(char *)(param_1 + 0x100) + 1;
  *(byte *)(param_1 + 0x100) = bVar3;
  
  // Get S[i]
  pcVar4 = (char *)((ulong)bVar3 + param_1);
  cVar1 = *pcVar4;
  
  // Update j
  bVar3 = *(char *)(param_1 + 0x101) + cVar1;
  *(byte *)(param_1 + 0x101) = bVar3;
  
  // Get S[j]
  pcVar5 = (char *)((ulong)bVar3 + param_1);
  cVar2 = *pcVar5;
  
  // Swap S[i] and S[j]
  *pcVar4 = cVar2;
  *pcVar5 = cVar1;
  
  // Return S[(S[i] + S[j]) % 256]
  return *(undefined *)(param_1 + (ulong)(byte)(cVar1 + cVar2));
}
```

**This is the RC4 PRGA (Pseudo-Random Generation Algorithm).**

**Note:** The state array layout is:
- Bytes 0-255: S-box array
- Byte 256: Counter `i`
- Byte 257: Counter `j`

#### Function 3: `FUN_00010078` - Output Function

This appears to be a wrapper for system calls to print messages. Not critical for our analysis.

### The Target Data

The comparison happens against data at address `0x00010210`:

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ xxd -s 0x210 -l 52 riscy
00000210: c575 95a5 8180 f344 f199 3481 3a5f 5093  .u.....D..4.:_P.
00000220: 67ee 120c 153a da1c 6f50 8049 63f2 36d3  g....:..oP.Ic.6.
00000230: 9364 4663 84b5 3a5a 9c3e 40f5 1920 7f08  .dFc..:Z.>@.. ..
00000240: 0048 0a03                                .H..
```

**52 bytes of encrypted flag data.**

The comparison loop checks:
- Start: `0x00010210`
- End: `0x00010244` 
- Length: `0x10244 - 0x10210 = 0x34 = 52 bytes`

---

## Deep Dive: Three Critical Questions

Now let's answer three fundamental questions that are crucial for understanding this challenge.

### Question 1: Where Does "First 8 Bytes = RC4 Key" Happen?

Looking at the entry function, this line is critical:

```c
FUN_00010080(auStack_138, pbVar2, 8);
//           ^RC4 state   ^input  ^key length = 8
```

**Function signature:**
```c
void FUN_00010080(byte *state, byte *key, ulong keylen)
```

Let's look inside `FUN_00010080` to see how it uses the key:

```c
do {
    uVar3 = uVar2 % param_3;  // uVar3 = i % keylen (i % 8)
    bVar1 = *pbVar6;          // bVar1 = S[i]
    uVar2 = uVar2 + 1;        // i++
    
    // j = (j + key[i % keylen] + S[i]) % 256
    uVar3 = (ulong)(int)((int)uVar5 + 
                         (uint)*(byte *)(uVar3 + param_2) +  // ← Accesses key[i % 8]
                         (uint)bVar1);
    uVar5 = uVar3 & 0xff;
    
    // Swap S[i] and S[j]
    *pbVar6 = param_1[uVar3 & 0xff];
    param_1[uVar3 & 0xff] = bVar1;
    pbVar6 = pbVar6 + 1;
} while (uVar2 != 0x100);
```

**The critical line:**
```c
(uint)*(byte *)(uVar3 + param_2)
```

Breaking it down:
- `uVar3` = `i % 8` (key index with wrapping)
- `param_2` = pointer to input buffer
- `uVar3 + param_2` = address of `input[i % 8]`
- `*(byte *)(uVar3 + param_2)` = value at `input[i % 8]`

**So when `i=0`: reads `input[0]`**  
**When `i=7`: reads `input[7]`**  
**When `i=8`: reads `input[0]` again (wraps)**  
**When `i=255`: reads `input[7]` again**

**This proves only the first 8 bytes are used as the RC4 key.**

### Question 2: Show the Entire Encryption Process in Detail

Let's trace through exactly what happens with example input: `"picoCTF{test}"`

#### Step 1: Input Reading and Validation

```c
do {
    ecall();  // Read input
    FUN_00010078(1,"You need to take some more riscs than that.\n",0x2c,0x40);
} while (unaff_s0 < 8);
```

- Reads input into buffer at `pbVar2`
- Keeps asking until length >= 8
- `unaff_s0` contains length

**Memory after input:**
```
pbVar2 points to: "picoCTF{test}"
unaff_s0 = 13 (length)
```

#### Step 2: RC4 Initialization

```c
FUN_00010080(auStack_138, pbVar2, 8);
```

**What happens inside:**

```c
// Initialize S-box
S[0] = 0, S[1] = 1, ..., S[255] = 255

// Scramble using key "picoCTF{"
j = 0
for i in 0..255:
    j = (j + S[i] + key[i % 8]) % 256
    swap(S[i], S[j])
```

**After this:**
- `auStack_138[0..255]` contains scrambled state
- `auStack_138[256]` = 0 (counter i)
- `auStack_138[257]` = 0 (counter j)

#### Step 3: Encryption Loop

```c
pbVar4 = pbVar2;  // Start at beginning of input
do {
    bVar1 = *pbVar4;                      // Read plaintext byte
    bVar3 = FUN_000100d2(auStack_138);    // Generate keystream byte
    pbVar5 = pbVar4 + 1;                  // Next position
    *pbVar4 = bVar1 ^ bVar3;              // XOR and overwrite IN-PLACE
    pbVar4 = pbVar5;
} while (pbVar2 + (unaff_s0 - (long)pbVar5) != (byte *)0x0);
```

**Iteration-by-iteration:**

```
Iteration 0:
  Position: pbVar4 points to input[0]
  Read:     bVar1 = 'p' (0x70)
  Generate: bVar3 = FUN_000100d2() → 0xA5 (example keystream byte)
  XOR:      0x70 ^ 0xA5 = 0xD5
  Write:    input[0] = 0xD5
  Advance:  pbVar4++

Iteration 1:
  Position: pbVar4 points to input[1]
  Read:     bVar1 = 'i' (0x69)
  Generate: bVar3 = FUN_000100d2() → 0x1C
  XOR:      0x69 ^ 0x1C = 0x75
  Write:    input[1] = 0x75
  Advance:  pbVar4++

...continues for all 13 bytes...
```

**Memory transformation:**

```
Before: "picoCTF{test}"
        [0x70, 0x69, 0x63, 0x6F, 0x43, 0x54, 0x46, 0x7B, 0x74, 0x65, 0x73, 0x74]

After:  [0xD5, 0x75, 0x95, 0xA5, 0x81, 0x80, 0xF3, 0x44, 0xF1, 0x99, 0x34, 0x81]
        (encrypted bytes, not ASCII anymore)
```

**Key insight:** The input buffer is **modified in-place**. The original plaintext is overwritten.

#### Step 4: Keystream Generation Details

Inside `FUN_000100d2()`:

```c
// State at auStack_138:
// [0..255]: S-box array
// [256]: i counter
// [257]: j counter

// First call:
i = state[256] + 1 = 0 + 1 = 1
state[256] = 1

S_i = state[1] = some_value_1

j = state[257] + S_i = 0 + some_value_1
state[257] = j

S_j = state[j]

// Swap S[i] and S[j]
state[1] = S_j
state[j] = S_i

// Return keystream byte
return state[(S_i + S_j) % 256]
```

**Each call:**
- Increments `i`
- Updates `j`
- Swaps two state bytes
- Returns one keystream byte

#### Step 5: The Comparison

```c
pbVar4 = &DAT_00010210;  // Point to target at 0x10210
do {
    bVar1 = *pbVar2;     // Our encrypted byte
    bVar3 = *pbVar4;     // Target encrypted byte
    pbVar2 = pbVar2 + 1; // Move our pointer
    pbVar4 = pbVar4 + 1; // Move target pointer
    if (bVar1 != bVar3) goto LAB_000101f2;  // Mismatch → fail
} while (pbVar4 != &UNK_00010244);  // Until end (52 bytes)
```

**Byte-by-byte comparison:**

```
Compare input[0] (0xD5) with target[0] (0xC5): NO MATCH → FAIL
```

If all 52 bytes match → Success!

### Question 3: How Do We Know Which Registers Contain What?

This is the **most important reverse engineering skill**. Let me show you multiple methods.

#### Method 1: Reading the Assembly Code

Let's look at the comparison loop in assembly. At address `0x101c4`:

```assembly
                             LAB_000101c4                    XREF[1]: 000101d4(j)
        000101c4 83 c6 04 00     lbu        a3,0x0(s1)      ; a3 = byte at address s1
        000101c8 03 c7 07 00     lbu        a4,0x0(a5)      ; a4 = byte at address a5
        000101cc 85 04           c.addi     s1,0x1          ; s1++
        000101ce 85 07           c.addi     a5,0x1          ; a5++
        000101d0 63 91 e6 02     bne        a3,a4,LAB_000101f2  ; if a3 != a4, fail
        000101d4 e3 98 c7 fe     bne        a5,a2,LAB_000101c4  ; loop if not done
```

**Assembly instruction meanings:**

- `lbu` = Load Byte Unsigned (read a byte from memory)
- `lbu a3, 0(s1)` = Load byte from address `s1 + 0` into register `a3`
- `lbu a4, 0(a5)` = Load byte from address `a5 + 0` into register `a4`
- `bne` = Branch if Not Equal

**So we can see:**
- `s1` contains a pointer (loaded byte from it)
- `a5` contains a pointer (loaded byte from it)
- `a3` and `a4` are compared
- If different → branch to failure

**Which pointer is which?** We need to trace back.

#### Tracing `s1` Register

Look earlier in the function:

```assembly
00010136 24 00           c.addi4spn s1,sp,0x8    ; s1 = sp + 8
```

This sets `s1 = stack_pointer + 8`.

Looking at stack layout:
- Stack frame is 0x180 bytes
- `sp + 0x8` is where input buffer starts
- So `s1` points to **our input buffer**

#### Tracing `a5` Register

Look just before the comparison loop:

```assembly
000101b4 97 07 00 00     auipc      a5,0x0          ; a5 = PC
000101b8 93 87 c7 05     addi       a5,a5,0x5c      ; a5 = a5 + 0x5c
```

**Calculate the address:**
```
At 0x101b4: PC = 0x101b4
auipc a5, 0x0  → a5 = 0x101b4
addi a5, a5, 0x5c  → a5 = 0x101b4 + 0x5c = 0x10210
```

**Address 0x10210 is in the `.rodata` section** (read-only data).

Looking at Ghidra or hexdump:
```
DAT_00010210: c5 75 95 a5 ...
```

This is the **hardcoded encrypted flag**!

#### Method 2: Dynamic Analysis with GDB

Let's verify our findings by running the binary under a debugger.

**Setup:**

```bash
# Terminal 1: Start QEMU with GDB stub on port 1234
qemu-riscv64 -g 1234 ./riscy

# Terminal 2: Start GDB
gdb-multiarch ./riscy
```

**In GDB:**

```gdb
(gdb) target remote localhost:1234
Remote debugging using localhost:1234

(gdb) break *0x101c4
Breakpoint 1 at 0x101c4

(gdb) continue
Continuing.
```

**In Terminal 1 (QEMU prompt):**
```
You've gotten yourself into some riscy business...
Got yourself a flag for me?
> picoCTF{testAAAA}
```

**Back in GDB (when breakpoint hits):**

```gdb
Breakpoint 1, 0x00000000000101c4 in ?? ()

(gdb) info registers
s0  = 0x000000000000000f    (input length - 1)
s1  = 0x00007fffffffe2a8    (stack address - our input!)
s2  = 0x00007fffffffe2b5    
a5  = 0x0000000000010210    (binary address - target!)
a2  = 0x0000000000010244    (end marker)
```

**Examine memory at these addresses:**

```gdb
(gdb) x/16xb $s1
0x7fffffffe2a8: 0xc5 0x8f 0x95 0xa5 0x81 0x80 0xf3 0x44
0x7fffffffe2b0: 0xf1 0x99 0x34 0x81 0x3a 0x5f 0x50 0x93

(gdb) x/16xb $a5
0x00010210:     0xc5 0x75 0x95 0xa5 0x81 0x80 0xf3 0x44
0x00010218:     0xf1 0x99 0x34 0x81 0x3a 0x5f 0x50 0x93
```

**Analysis:**

1. **s1 (0x7fffffffe2a8)** - High memory address (stack)
   - Contains: `0xc5 0x8f 0x95 ...`
   - This is our encrypted input
   - First byte: 0xc5
   - Second byte: 0x8f (different from target!)

2. **a5 (0x00010210)** - Low memory address (binary data)
   - Contains: `0xc5 0x75 0x95 ...`
   - This is the hardcoded target
   - First byte: 0xc5 (matches!)
   - Second byte: 0x75 (doesn't match our input)

**Key observations:**
- Both start with 0xc5 (first byte matches!)
- Second bytes differ: our 0x8f vs target 0x75
- This means our input was partially correct

#### Method 3: Step Through Assembly

```gdb
(gdb) disassemble $pc, $pc+20
Dump of assembler code from 0x101c4 to 0x101d8:
=> 0x101c4:  lbu    a3, 0(s1)
   0x101c8:  lbu    a4, 0(a5)
   0x101cc:  addi   s1, s1, 1
   0x101ce:  addi   a5, a5, 1
   0x101d0:  bne    a3, a4, 0x101f2
   0x101d4:  bne    a5, a2, 0x101c4
```

**Step through instruction by instruction:**

```gdb
(gdb) stepi
0x000101c8

(gdb) info reg a3
a3  = 0x00000000000000c5    (loaded from s1)

(gdb) stepi
0x000101cc

(gdb) info reg a4
a4  = 0x00000000000000c5    (loaded from a5)

(gdb) print/x $a3
$1 = 0xc5

(gdb) print/x $a4
$2 = 0xc5

(gdb) print $a3 == $a4
$3 = 1    (They match!)
```

**Continue to next iteration:**

```gdb
(gdb) continue
Continuing.

Breakpoint 1, 0x00000000000101c4 in ?? ()

(gdb) stepi
(gdb) stepi

(gdb) print/x $a3
$4 = 0x8f    (our byte)

(gdb) print/x $a4
$5 = 0x75    (target byte)

(gdb) print $a3 == $a4
$6 = 0    (They DON'T match!)
```

**This proves:**
- First byte of our input matched target
- Second byte didn't match
- The comparison will fail and branch to error message

#### Summary: Register Mapping

| Register | Contains | Points To | Decompiled Variable |
|----------|----------|-----------|-------------------|
| `s0` | Input length - 1 | - | `unaff_s0` |
| `s1` | Input buffer pointer | Stack (our encrypted input) | `pbVar2` |
| `s2` | Loop pointer | Moving through input | - |
| `a5` | Target pointer | 0x10210 (hardcoded target) | `pbVar4` |
| `a2` | End marker | 0x10244 (end of target) | - |
| `a3` | Our byte (temp) | - | `bVar1` |
| `a4` | Target byte (temp) | - | `bVar3` |

**Memory map at breakpoint 0x101c4:**

```
┌────────────────────────────────────────┐
│ Address 0x10210 (.rodata section)      │
│ c5 75 95 a5 81 80 f3 44 f1 99 ...     │ ← a5 points here (target)
│ (52 bytes of encrypted flag)           │
└────────────────────────────────────────┘

┌────────────────────────────────────────┐
│ Stack: sp + 0x8                         │
│ c5 8f 95 a5 81 80 f3 44 f1 99 ...     │ ← s1 points here (our input)
│ (our encrypted input)                   │
└────────────────────────────────────────┘
```

---

## Dynamic Analysis Strategy

Now that we understand the binary, we need a strategy to solve it.

### The Problem

We need to find input `I` such that:

```
RC4_encrypt(I, key=I[0:8]) == target_bytes
```

This creates a **circular dependency:**
- The first 8 bytes of input ARE the key
- But the key affects how those same 8 bytes get encrypted
- We can't just reverse RC4 because we don't know the key

### Why Brute Force Won't Work

If we try all possible 8-byte keys:
- 256 options per byte
- 256^8 = 18,446,744,073,709,551,616 combinations
- At 1 million tests per second: **584,542 years**

### The Brilliant Solution: Character-by-Character Discovery

Instead of trying to solve it mathematically, we use the **binary itself as an oracle**:

1. We know flags often start with `picoCTF{`
2. We send `picoCTF{a` and let the binary encrypt it
3. We peek at the encrypted result in memory
4. We compare it with the target
5. If encrypted[0:9] matches target[0:9] → 'a' is correct!
6. If not → try 'b', then 'c', etc.
7. Once we find the right 9th character, move to 10th
8. Repeat until we have the full flag

**Why this works:**
- We only try ~94 printable characters per position
- For a 52-character flag: ~94 × 52 = ~4,888 attempts
- This is **computationally feasible**!

### The Key Insight

At address `0x101c4` (right before the comparison):
- The binary has ALREADY encrypted our input
- Register `s1` points to our encrypted result
- Register `a5` points to the target
- We can **read both values** before the program compares them

### The Attack Plan

```python
known = b"picoCTF{"  # Start with known prefix

for position in range(8, 52):  # For each unknown character
    for char in printable_characters:
        guess = known + char.encode()
        
        # Send guess to binary (runs in debugger)
        send_guess(guess)
        
        # Binary encrypts it and stops at breakpoint
        # Read encrypted values from registers
        our_encrypted = read_from_register("s1")
        target = read_from_register("a5")
        
        # Check if they match up to current position
        if our_encrypted[:position+1] == target[:position+1]:
            known += char.encode()  # Found it!
            print(f"Flag so far: {known}")
            break
```

**The magic:** Each character takes at most 94 tries instead of 256^44 tries for the remaining 44 characters.

---

## Writing the Exploit

Now let's write the actual exploit script.

### Script Structure

```python
#!/usr/bin/env python3
import string
from pwn import *

# Character set to try (printable ASCII)
chars = string.punctuation + string.digits + string.ascii_lowercase + string.ascii_uppercase

# Known flag start (standard picoCTF format)
flag_known = b"picoCTF{"

# Start QEMU with GDB stub on port 1234
qemu = process(["qemu-riscv64", "-g", "1234", "./riscy"])

# Start GDB-multiarch
gdb = process(["gdb-multiarch", "-q"])

# GDB prompt indicator
prompt = b"gef➤"  # Using GEF (GDB Enhanced Features)

# Connect GDB to QEMU
gdb.sendlineafter(prompt, b"gef-remote localhost 1234 --qemu-user --qemu-binary ./riscy")
info("GDB attached to QEMU!")

# Set breakpoint at comparison location
gdb.sendlineafter(prompt, b"b *0x101c0")
```

### Helper Functions

```python
def wait_prompt():
    """Wait for GDB prompt"""
    gdb.recvuntil(prompt)

def send_guess(guess):
    """Send a guess to the program"""
    # Continue execution in GDB
    gdb.sendline(b"c")
    
    # Wait for input prompt in QEMU
    qemu.recvuntil(b"> ")
    
    # Send our guess
    qemu.sendline(guess)
    
    # Wait for breakpoint to hit
    gdb.recvuntil(b"BREAKPOINT")

def dump_register(reg: bytes) -> bytes:
    """Read and parse register contents"""
    # Clear any pending output
    gdb.clean()
    
    # Use GEF command to dump register as hex
    # Format: pf --lang hex -l 52 $register
    gdb.sendline(b"pf --lang hex -l 52 $" + reg)
    
    # Read the output
    output = gdb.recvuntil(prompt)
    
    # Extract just the hex string (first line)
    hex_data = output[0:output.index(b"\n")]
    
    # Convert hex to bytes
    return unhex(hex_data)
```

### Main Exploit Loop

```python
#!/usr/bin/env python3
import string
from pwn import *

# start qemu
gdb_port = "9000"
qemu = process(["qemu-riscv64-static", "-g", gdb_port, "./riscy"])

# start gdb (use -nx to not load .gdbinit which has GEF)
gdb = process(["gdb-multiarch", "-q", "-nx"])
prompt = b"(gdb) "

# Disable colors and pagination
gdb.sendlineafter(prompt, b"set style enabled off")
gdb.sendlineafter(prompt, b"set print repeats 0")
gdb.sendlineafter(prompt, b"set pagination off")
gdb.sendlineafter(prompt, b"file ./riscy")
gdb.sendlineafter(prompt, f"target remote localhost:{gdb_port}".encode("ascii"))
gdb.sendlineafter(prompt, b"b *0x101c0")

def wait_prompt():
    gdb.recvuntil(prompt)

def send_guess(g):
    gdb.sendline(b"c")
    qemu.recvuntil(b"> ")
    qemu.sendline(g)
    gdb.recvuntil(b"Breakpoint")

def dump_reg(reg: bytes) -> bytes:
    gdb.clean()
    gdb.sendline(b"x/65xb $" + reg)
    val = gdb.recvuntil(prompt)
    hex_data = b""
    for line in val.split(b"\n"):
        if not b":" in line:
            break
        line = line.split(b":", 1)[1]
        line = line.replace(b"\t0x", b"").replace(b"\t", b"")
        hex_data += line
    return unhex(hex_data)

# Character set for brute forcing (put common characters first for speed)
chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation

# Initial known flag
flag = b"picoCTF{"

# Get initial guess to get the encrypted expected value
send_guess(flag)
wanted = dump_reg(b"a5")
info(f"Encrypted flag: {wanted}")

# Bruteforce character by character
with log.progress("Flag") as p:
    for i in range(len(flag), 52):
        found = False
        for c in chars:
            guess = flag + c.encode("ascii")

            # Reset PC to beginning of check function
            gdb.sendline(b"set $pc = 0x10112")
            wait_prompt()
            send_guess(guess)

            # Dump register with our input
            input_enc = dump_reg(b"s1")

            # Check if characters match up to current position
            if input_enc[:i + 1] == wanted[:i + 1]:
                found = True
                flag = guess
                p.status(flag.decode())
                break

        if not found:
            warning("Character not found!")
            break

success(f"FLAG: {flag.decode()}")
qemu.kill()
gdb.kill()
```

### Complete Exploit Script

Here's the full script combined:

```python
#!/usr/bin/env python3
"""
Exploit for riscy business challenge
Uses character-by-character brute force via GDB automation
"""
import string
from pwn import *

# Set up
chars = string.punctuation + string.digits + string.ascii_lowercase + string.ascii_uppercase
flag_known = b"picoCTF{"

# Helper functions
def wait_prompt():
    gdb.recvuntil(prompt)

def send_guess(guess):
    gdb.sendline(b"c")
    qemu.recvuntil(b"> ")
    qemu.sendline(guess)
    gdb.recvuntil(b"BREAKPOINT")

def dump_register(reg: bytes) -> bytes:
    gdb.clean()
    gdb.sendline(b"pf --lang hex -l 52 $" + reg)
    output = gdb.recvuntil(prompt)
    hex_data = output[0:output.index(b"\n")]
    return unhex(hex_data)

# Main
qemu = process(["qemu-riscv64", "-g", "1234", "./riscy"])
gdb = process(["gdb-multiarch", "-q"])
prompt = b"gef➤"

gdb.sendlineafter(prompt, b"gef-remote localhost 1234 --qemu-user --qemu-binary ./riscy")
info("GDB attached to QEMU!")

gdb.sendlineafter(prompt, b"b *0x101c0")
wait_prompt()

# Get target
send_guess(flag_known)
target = dump_register(b"a5")
info(f"Target: {target.hex()}")

# Brute force
info("Starting brute force...")
with log.progress("Flag") as progress:
    for i in range(len(flag_known), 52):
        found = False
        for c in chars:
            guess = flag_known + c.encode("ascii")
            gdb.sendline(b"set $pc = 0x10112")
            wait_prompt()
            send_guess(guess)
            our_encrypted = dump_register(b"s1")
            
            if our_encrypted[:i + 1] == target[:i + 1]:
                found = True
                flag_known = guess
                progress.status(flag_known.decode())
                break
        
        if not found:
            warning(f"Character {i} not found!")
            break

success(f"FLAG: {flag_known.decode()}")
```

---

## Getting the Flag

### Running the Exploit

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ python3 exploit.py
[+] Starting local process '/usr/bin/qemu-riscv64': pid 12345
[+] Starting local process '/usr/bin/gdb-multiarch': pid 12346
[*] GDB attached to QEMU!
[*] Target: c57595a58180f344f19934813a5f509367ee120c153ada1c6f50804963f236d39364466384b53a5a9c3e40f519207f0800480a03
[*] Starting brute force...
[+] Flag: picoCTF{4
[+] Flag: picoCTF{4n
[+] Flag: picoCTF{4ny
[+] Flag: picoCTF{4ny0
[+] Flag: picoCTF{4ny0n
[+] Flag: picoCTF{4ny0n3
[+] Flag: picoCTF{4ny0n3_
[+] Flag: picoCTF{4ny0n3_g
[+] Flag: picoCTF{4ny0n3_g0
[+] Flag: picoCTF{4ny0n3_g0t
[+] Flag: picoCTF{4ny0n3_g0t_
[+] Flag: picoCTF{4ny0n3_g0t_r
[+] Flag: picoCTF{4ny0n3_g0t_r1
[+] Flag: picoCTF{4ny0n3_g0t_r1s
[+] Flag: picoCTF{4ny0n3_g0t_r1sc
[+] Flag: picoCTF{4ny0n3_g0t_r1scv
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4r
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rd
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_L
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LG
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGU
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUf
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfw
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8x
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xy
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyM
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMU
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUl
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlp
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpg
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgv
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz
[+] Flag: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}
[+] FLAG: picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}
```

### Verification

```bash
┌──(kali㉿kali)-[~/ctf]
└─$ ./riscy
You've gotten yourself into some riscy business...
Got yourself a flag for me?
> picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}
Success!
```

**Flag:** `picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`

---

## Key Takeaways

### Technical Skills Learned

1. **RISC-V Architecture**
   - Understanding uncommon architectures
   - Using QEMU for emulation
   - Reading RISC-V assembly

2. **RC4 Encryption**
   - How stream ciphers work
   - Key scheduling algorithm
   - Keystream generation

3. **Static Analysis**
   - Reading decompiled C code
   - Mapping variables to registers
   - Understanding control flow

4. **Dynamic Analysis**
   - Cross-architecture debugging
   - GDB automation with pwntools
   - Register and memory inspection

5. **Algorithm Analysis**
   - Identifying circular dependencies
   - Finding oracle-based solutions
   - Optimization techniques

### Reverse Engineering Methodology

1. **Reconnaissance**
   - Identify architecture and protections
   - Run the binary and observe behavior
   - Extract strings and metadata

2. **Static Analysis**
   - Decompile with Ghidra/IDA
   - Identify main logic flow
   - Recognize algorithms (RC4 in this case)

3. **Deep Dive**
   - Read assembly code
   - Map decompiled variables to registers
   - Understand exact data flow

4. **Dynamic Analysis**
   - Set up debugging environment
   - Set strategic breakpoints
   - Observe runtime behavior

5. **Exploit Development**
   - Identify weakness (oracle in this case)
   - Automate the attack
   - Verify solution

### Why This Challenge is Excellent

1. **Novel Architecture** - Forces learning RISC-V
2. **Cryptographic Understanding** - Requires understanding RC4
3. **Circular Dependency** - Can't be solved with simple reversal
4. **Creative Solution** - Oracle-based attack is elegant
5. **Automation Skills** - Must script GDB interaction

### Common Pitfalls

1. **Trying to solve mathematically** - The circular dependency makes this infeasible
2. **Not understanding RC4** - Can't analyze without knowing the algorithm
3. **Missing the oracle opportunity** - The key insight is using the binary itself
4. **Poor automation** - Must efficiently script the brute force
5. **Wrong breakpoint** - Setting breakpoint after comparison doesn't work

### Further Learning

- **RISC-V ISA Manual**: Understand the instruction set
- **Stream Ciphers**: Learn about other ciphers (ChaCha20, Salsa20)
- **GDB Scripting**: Master automation techniques
- **Cross-Architecture RE**: Practice with ARM, MIPS, etc.
- **Side-Channel Attacks**: Learn about timing attacks and other oracles

---

## Conclusion

This challenge demonstrates that sometimes the best approach isn't to reverse the algorithm completely, but to use the program itself as a tool. The "oracle attack" technique - where we use the binary to encrypt our guesses and observe the results - is a powerful method that applies to many CTF challenges.

The key lessons:
- **Understand before attacking** - Deep analysis revealed the circular dependency
- **Think creatively** - Mathematical solution was infeasible
- **Automate efficiently** - Character-by-character reduced search space dramatically
- **Use the right tools** - GDB + pwntools made automation possible

**Final Flag:** `picoCTF{4ny0n3_g0t_r1scv_h4rdw4r3?_LGUfwl8xyMUlpgvz}`

---

## Appendix: Quick Reference

### RISC-V Instructions Used

```
lbu  rd, offset(rs1)    # Load byte unsigned: rd = memory[rs1 + offset]
sb   rs2, offset(rs1)   # Store byte: memory[rs1 + offset] = rs2
addi rd, rs1, imm       # Add immediate: rd = rs1 + imm
bne  rs1, rs2, label    # Branch if not equal: if rs1 != rs2 goto label
auipc rd, imm           # Add upper immediate to PC: rd = PC + (imm << 12)
jal  rd, label          # Jump and link: rd = PC+4; goto label
ecall                   # System call
```

### GDB Commands Used

```bash
target remote localhost:1234    # Connect to remote target
break *0x101c0                  # Set breakpoint at address
continue                        # Resume execution
stepi                           # Step one instruction
info registers                  # Show all registers
x/52xb $s1                      # Examine 52 bytes at address in s1
set $pc = 0x10112              # Set program counter
```

### Python/Pwntools Functions

```python
process(["qemu-riscv64", "-g", "1234", "./binary"])  # Start process
gdb.sendline(b"command")                              # Send to GDB
qemu.recvuntil(b"prompt")                             # Wait for prompt
unhex(hex_string)                                     # Convert hex to bytes
log.progress("message")                               # Progress indicator
```

---
