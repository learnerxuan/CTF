# Classic Crackme 0x100 - Complete Writeup

## Challenge Information
- **Challenge Name:** Classic Crackme 0x100
- **Category:** Reverse Engineering
- **Difficulty:** Medium
- **Objective:** Find the password that the binary accepts to get the flag

---

## Table of Contents
1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Static Analysis with Ghidra](#static-analysis-with-ghidra)
3. [Understanding Memory Layout](#understanding-memory-layout)
4. [Dynamic Analysis with GDB/pwndbg](#dynamic-analysis-with-gdb-pwndbg)
5. [Algorithm Analysis](#algorithm-analysis)
6. [Solution Development](#solution-development)
7. [Key Concepts & Common Confusions](#key-concepts--common-confusions)
8. [Final Solution](#final-solution)

---

## Initial Reconnaissance

### Basic File Analysis
```bash
file crackme100
```

**Output:**
```
crackme100: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), 
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
for GNU/Linux 3.2.0, with debug_info, not stripped
```

**What this tells us:**
- **ELF 64-bit:** Linux executable, 64-bit architecture
- **x86-64:** Intel/AMD processor instructions
- **Dynamically linked:** Uses shared libraries
- **with debug_info, not stripped:** 🎯 IMPORTANT - Has debugging symbols and function names intact

### Security Protections
```bash
checksec --file=crackme100
```

**Output:**
```
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE
```

**What this means:**
- **No Stack Canary:** No protection against buffer overflows
- **NX enabled:** Stack is not executable (prevents shellcode on stack)
- **No PIE:** Addresses are fixed (not randomized)

### String Analysis
```bash
strings crackme100 | grep -i flag
strings crackme100 | grep -i password
```

**Findings:**
- `picoCTF{sample_flag}` - This is just a placeholder
- `Enter the secret password:` - The prompt message
- **No plaintext password found** - This means the password is not hardcoded as a string

### Initial Test Run
```bash
./crackme100
```

**Behavior:**
- Prompts: "Enter the secret password:"
- Input: `test123`
- Output: `FAILED!`

**Conclusion:** The program compares our input against something, but we can't just grep for the password in strings.

---

## Static Analysis with Ghidra

### Loading the Binary

1. Open Ghidra
2. Create new project
3. Import `crackme100`
4. Auto-analyze (accept defaults)
5. Navigate to `main` function in Symbol Tree

### Decompiled Code Analysis
```c
undefined8 main(void)
{
  int iVar1;
  size_t sVar2;
  char local_a8 [64];
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined7 local_40;
  undefined4 uStack_39;
  uint local_2c;
  uint local_28;
  char local_21;
  uint local_20;
  uint local_1c;
  uint local_18;
  int local_14;
  int local_10;
  int local_c;
  
  // Target string setup
  local_68 = 0x676d76727970786c;
  local_60 = 0x7672657270697564;
  local_58 = 0x727166766b716f6d;
  local_50 = 0x6575717670716c62;
  local_48 = 0x796771706d7a7565;
  local_40 = 0x73687478726963;
  uStack_39 = 0x77616a;
  
  setvbuf(stdout,(char *)0x0,2,0);
  printf("Enter the secret password: ");
  __isoc99_scanf(&DAT_00402024,local_a8);
  
  local_c = 0;
  sVar2 = strlen((char *)&local_68);
  local_14 = (int)sVar2;
  local_18 = 0x55;
  local_1c = 0x33;
  local_20 = 0xf;
  local_21 = 'a';
  
  // Triple nested transformation
  for (; local_c < 3; local_c = local_c + 1) {
    for (local_10 = 0; local_10 < local_14; local_10 = local_10 + 1) {
      local_28 = (local_10 % 0xff >> 1 & local_18) + (local_10 % 0xff & local_18);
      local_2c = ((int)local_28 >> 2 & local_1c) + (local_1c & local_28);
      iVar1 = ((int)local_2c >> 4 & local_20) +
              ((int)local_a8[local_10] - (int)local_21) + (local_20 & local_2c);
      local_a8[local_10] = local_21 + (char)iVar1 + (char)(iVar1 / 0x1a) * -0x1a;
    }
  }
  
  iVar1 = memcmp(local_a8,&local_68,(long)local_14);
  if (iVar1 == 0) {
    printf("SUCCESS! Here is your flag: %s\n","picoCTF{sample_flag}");
  }
  else {
    puts("FAILED!");
  }
  return 0;
}
```

### The "Story Following" Method

Every program tells a story. Let's follow it:
```
START (main)
   ↓
[1] Setup target string (local_68, local_60, etc.)
   ↓
[2] Read user input into local_a8 (max 64 bytes)
   ↓
[3] Transform input 3 times (nested loops)
   ↓
[4] Compare transformed input to target (memcmp)
   ↓
[5] SUCCESS or FAIL
```

### Key Observations

**1. Input Storage:**
```c
char local_a8 [64];
__isoc99_scanf(&DAT_00402024, local_a8);
```
- Input stored in `local_a8` buffer (max 64 bytes)

**2. Transformation:**
```c
for (; local_c < 3; local_c = local_c + 1) {
    for (local_10 = 0; local_10 < local_14; local_10 = local_10 + 1) {
```
- Outer loop: 3 iterations
- Inner loop: Each character position
- **Pattern:** This scrambles each character 3 times

**3. The Comparison:**
```c
iVar1 = memcmp(local_a8, &local_68, (long)local_14);
```
- Compares scrambled input to target
- Uses `memcmp` (byte-by-byte comparison)
- Length is `local_14` (calculated from strlen of target)

---

## Understanding Memory Layout

### The Confusion: Multiple Variables Form One String

**Original Question:** 
> "I thought local_68, local_60, local_58... are separate variables. How do they combine together?"

**The Answer:**

When you see this in Ghidra:
```c
local_68 = 0x676d76727970786c;
local_60 = 0x7672657270697564;
local_58 = 0x727166766b716f6d;
// etc...
```

These variables are stored **consecutively in memory** on the stack:
```
Memory Layout (Stack):
┌─────────────┬──────────────────────┬─────────┐
│ Address     │ Variable             │ Value   │
├─────────────┼──────────────────────┼─────────┤
│ rbp-0x68    │ local_68 (8 bytes)   │ lxpyrvmg│
│ rbp-0x60    │ local_60 (8 bytes)   │ duiprerv│
│ rbp-0x58    │ local_58 (8 bytes)   │ moqkvfqr│
│ rbp-0x50    │ local_50 (8 bytes)   │ blqpvque│
│ rbp-0x48    │ local_48 (8 bytes)   │ euzmpqgy│
│ rbp-0x40    │ local_40 (7 bytes)   │ cirxthsj│
│ rbp-0x39    │ uStack_39 (3 bytes)  │ aw\0    │
└─────────────┴──────────────────────┴─────────┘
```

### How strlen() Reads Through Multiple Variables
```c
sVar2 = strlen((char *)&local_68);
```

**Key insight:** `strlen()` doesn't know about variable names. It just reads bytes starting from the address `&local_68` until it hits a null byte (`\0`).

**Memory Reading Example:**
```c
char a = 'H';
char b = 'e';
char c = 'l';
char d = 'l';
char e = 'o';
char f = '\0';

strlen(&a);  // Returns 5 - reads through ALL variables until \0
```

### The `&` Operator and Consecutive Memory

**Question:** 
> "What does `&local_68` mean? How is it related to other variables?"

**Answer:**

- `local_68` = the value stored in that variable
- `&local_68` = the **memory address** where that variable starts

When you pass `&local_68` to a function like `strlen()` or `memcmp()`, you're saying:
- "Start reading from this address"
- "Keep reading consecutive bytes"
- "Stop when you hit a null terminator (for strlen) or reach n bytes (for memcmp)"

### Type Casting Explained

**Question:**
> "I don't know what type casting is"

**Type Casting** = telling the compiler to treat data as a different type.

**Example:**
```c
int x = 50;
long y = (long)x;  // Cast int to long
```

**In the challenge:**
```c
iVar1 = memcmp(local_a8, &local_68, (long)local_14);
```

- `local_14` is type `int` 
- `(long)local_14` casts it to type `long`
- The VALUE doesn't change (still 50)
- Just ensures type compatibility with memcmp's expected parameter type

---

## Dynamic Analysis with GDB/pwndbg

### Why Use GDB?

**Static analysis (Ghidra)** shows us the code, but:
- Hex values are confusing to decode
- We might misread byte order (endianness)
- We need to verify our understanding

**Dynamic analysis (GDB)** lets us:
- See actual values at runtime
- Inspect memory directly
- Verify assumptions

### The x86-64 Calling Convention

**Critical Knowledge:** In x86-64 Linux, function arguments are passed in specific registers:
```
Function Call:  someFunc(arg1, arg2, arg3, arg4, arg5, arg6)
Registers:               RDI   RSI   RDX   RCX   R8    R9
```

**For memcmp(s1, s2, n):**
- `s1` (first string) → **RDI**
- `s2` (second string) → **RSI**
- `n` (number of bytes) → **RDX**

**You must memorize this rule** - it applies to all x86-64 Linux programs.

### Setting Breakpoints - The Strategy

**Question:**
> "I don't know where to put breakpoints, what to observe, how to think"

**The Breakpoint Strategy Framework:**

Set breakpoints at:
1. **Decision points:** Where the program makes choices (if statements, comparisons)
2. **State changes:** Where data gets modified (assignments, transformations)

**For this challenge, the critical breakpoint:**
```assembly
0x40136a:  call   memcmp@plt    # ← Break HERE (before comparison)
0x40136f:  test   eax, eax      # After comparison (result in eax)
```

**Why break BEFORE memcmp?**
- You can examine BOTH strings being compared
- Arguments are already set up in registers (RDI, RSI, RDX)
- You see the "final state" before the decisive comparison

### GDB Session Walkthrough

#### Step 1: Start pwndbg
```bash
pwndbg crackme100
```

#### Step 2: Set Breakpoint at memcmp Call
```bash
break *0x40136a
```

**Why this address?**
- From Ghidra assembly, find the `call memcmp` instruction
- Get its address (0x40136a in this case)
- This stops execution RIGHT BEFORE memcmp runs

#### Step 3: Run and Provide Input
```bash
run
# When prompted, enter: aaaaaaaaaa
```

#### Step 4: Examine Registers
```bash
info registers rdi rsi rdx
```

**Output:**
```
rdi  0x7fffffffd940  ◂— 'addgdggj...'
rsi  0x7fffffffd980  ◂— 'lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw'
rdx  0x32
```

**What pwndbg shows you automatically:**
```
► call   memcmp@plt
    s1: 0x7fffffffd940 ◂— 'addgdggj...'
    s2: 0x7fffffffd980 ◂— 'lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw'
    n: 0x32
```

**Key Observations:**

1. **RDI (your scrambled input):** `addgdggj...`
   - You typed "aaaaaaaaaa" (10 a's)
   - After 3 scrambles, it became "addgdggj..."

2. **RSI (the target):** `lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw`
   - This is the REAL target string from memory
   - 50 characters long (RDX = 0x32 = 50 in decimal)

3. **RDX (comparison length):** `0x32` = 50 bytes

### Why Dynamic Analysis Was Critical

**Problem we had:** When reading Ghidra's hex values:
```c
local_68 = 0x676d76727970786c;
```

We initially misread the byte order due to **little-endian** format.

**Solution:** GDB showed us the actual string in memory:
```
lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw
```

This is the CORRECT target we need to reverse.

---

## Algorithm Analysis

### The Transformation Code
```c
for (; local_c < 3; local_c = local_c + 1) {                    // Outer loop: 3 times
    for (local_10 = 0; local_10 < local_14; local_10 = local_10 + 1) {  // Inner: each char
      local_28 = (local_10 % 0xff >> 1 & local_18) + (local_10 % 0xff & local_18);
      local_2c = ((int)local_28 >> 2 & local_1c) + (local_1c & local_28);
      iVar1 = ((int)local_2c >> 4 & local_20) +
              ((int)local_a8[local_10] - (int)local_21) + (local_20 & local_2c);
      local_a8[local_10] = local_21 + (char)iVar1 + (char)(iVar1 / 0x1a) * -0x1a;
    }
  }
```

### Breaking Down the Algorithm

**Constants:**
```c
local_18 = 0x55;  // Binary: 01010101
local_1c = 0x33;  // Binary: 00110011
local_20 = 0xf;   // Binary: 00001111
local_21 = 'a';   // Base character
```

**The transformation happens in stages:**

#### Stage 1: Calculate offset based on position
```c
local_28 = (local_10 % 0xff >> 1 & 0x55) + (local_10 % 0xff & 0x55);
local_2c = ((int)local_28 >> 2 & 0x33) + (0x33 & local_28);
offset = ((int)local_2c >> 4 & 0xf) + (0xf & local_2c);
```

**Key insight:** The offset depends ONLY on position (`local_10`), NOT on the character value.

#### Stage 2: Apply Caesar cipher shift
```c
char_value = local_a8[local_10] - 'a';           // Convert to 0-25
new_value = char_value + offset;                 // Add offset
result = (new_value % 26);                       // Wrap around alphabet
local_a8[local_10] = 'a' + result;              // Convert back to char
```

The line:
```c
local_a8[local_10] = local_21 + (char)iVar1 + (char)(iVar1 / 0x1a) * -0x1a;
```

Is equivalent to:
```c
local_a8[local_10] = 'a' + (iVar1 % 26);
```

The `(iVar1 / 0x1a) * -0x1a` part is manually calculating modulo 26 (since 0x1a = 26).

### Simplified Algorithm
```
For each character at position P:
  1. Calculate offset based on P (using bitwise operations)
  2. Convert char to number: 'a'=0, 'b'=1, ..., 'z'=25
  3. new_value = (old_value + offset) mod 26
  4. Convert back to letter
  
Repeat entire process 3 times
```

### Example Trace

**Input:** 'a' at position 0

**Iteration 1:**
- Position: 0
- Offset calculation: 0 (position 0 gives offset 0)
- Character: 'a' → 0
- Transform: (0 + 0) mod 26 = 0 → 'a'

**Input:** 'a' at position 1

**Iteration 1:**
- Position: 1  
- Offset calculation: 5 (example)
- Character: 'a' → 0
- Transform: (0 + 5) mod 26 = 5 → 'f'

---

## Solution Development

### The Reversal Logic

**Forward transformation:**
```
new_char = (old_char + offset) mod 26
```

**Reverse transformation:**
```
old_char = (new_char - offset) mod 26
```

**Why this works:**
```
Forward:  x + offset = y (mod 26)
Reverse:  y - offset = x (mod 26)

Example:
- Original: 'c' (value 2)
- Offset: 7
- Forward: (2 + 7) mod 26 = 9 = 'j'
- Reverse: (9 - 7) mod 26 = 2 = 'c' ✓
```

### Handling Negative Results

When subtracting, we might get negative numbers:
```python
char_value = ord('b') - ord('a')  # = 1
offset = 5
new_value = (1 - 5) % 26  # = -4 % 26 = 22 = 'w'
```

Python's modulo automatically handles negatives correctly!

### Number of Iterations

**Question:**
> "The program scrambles 3 times. How many times do we unscramble?"

**Answer:** 3 times
```
Password → Scramble → Scramble → Scramble → Target
Target → Unscramble → Unscramble → Unscramble → Password
```

### The Python Solution
```python
#!/usr/bin/env python3

def reverse_transform(password):
    """
    Reverse one iteration of the scrambling algorithm.
    """
    result = list(password)
    length = len(password)
    
    # Constants from the binary
    local_18 = 0x55
    local_1c = 0x33
    local_20 = 0xf
    
    for pos in range(length):
        # Calculate offset for this position (EXACT same as binary)
        local_28 = ((pos % 0xff) >> 1 & local_18) + ((pos % 0xff) & local_18)
        local_2c = ((local_28 >> 2) & local_1c) + (local_1c & local_28)
        offset = ((local_2c >> 4) & local_20) + (local_20 & local_2c)
        
        # Get current character value (0-25)
        char_value = ord(result[pos]) - ord('a')
        
        # REVERSE: Subtract offset instead of add
        new_value = (char_value - offset) % 26
        
        # Convert back to character
        result[pos] = chr(ord('a') + new_value)
    
    return ''.join(result)

# CORRECT target from GDB (not from Ghidra hex values!)
scrambled = "lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw"

print(f"Target (scrambled): {scrambled}")
print(f"Length: {len(scrambled)}")

# Reverse 3 times
password = scrambled
for iteration in range(3):
    password = reverse_transform(password)
    print(f"After reverse iteration {iteration + 1}: {password}")

print(f"\n[+] Original password: {password}")
```

### Running the Solution
```bash
python3 solve.py
```

**Output:**
```
Target (scrambled): lxpyrvmgduiprervmoqkvfqrblqpvqueeuzmpqgycirxthsjaw
Length: 50
After reverse iteration 1: lwowqtkdcsgmpborlmohtcnnzinlsmqzdsxjnnduafotqdoeyt
After reverse iteration 2: lvnupriabqejnylnkkmerzkjxfkhpimucqvglkaqyclpnzkzwq
After reverse iteration 3: lumsopgxaocglvijjikbpwhfvchdmeipbotdjhxmwzilkvguun

[+] Original password: lumsopgxaocglvijjikbpwhfvchdmeipbotdjhxmwzilkvguun
```

### Verification
```bash
./crackme100
# Enter: lumsopgxaocglvijjikbpwhfvchdmeipbotdjhxmwzilkvguun
```

**Output:**
```
SUCCESS! Here is your flag: picoCTF{sample_flag}
```

**On the server:**
```bash
nc titan.picoctf.net 62694
# Enter: lumsopgxaocglvijjikbpwhfvchdmeipbotdjhxmwzilkvguun
```

**Output:**
```
SUCCESS! Here is your flag: picoCTF{s0lv3_angry_symb0ls_150f8acd}
```

**FLAG:** `picoCTF{s0lv3_angry_symb0ls_150f8acd}`

---

## Key Concepts & Common Confusions

### 1. Memory Layout and Consecutive Variables

**Confusion:** 
> "How do separate variables (local_68, local_60, etc.) form one continuous string?"

**Concept:**

Variables declared one after another in C are stored **consecutively** in memory:
```c
char a = 'H';
char b = 'i';
char c = '\0';
```

Memory looks like:
```
[Address 0x1000]: 'H'  ← variable a
[Address 0x1001]: 'i'  ← variable b  
[Address 0x1002]: '\0' ← variable c
```

When you call `strlen(&a)`, it:
1. Starts at address of `a`
2. Reads consecutive bytes
3. Doesn't care about variable names
4. Stops at null terminator

**The & Operator:**
- `a` = the value ('H')
- `&a` = the address where 'H' is stored

### 2. Little-Endian Byte Order

**Confusion:**
> "Why does Ghidra show 0x676d76727970786c but the actual string is different?"

**Concept:**

x86-64 uses **little-endian** byte order:
```
Hex value:     0x676d76727970786c
Memory bytes:  6c 78 70 79 72 76 6d 67  (reversed!)
String:        l  x  p  y  r  v  m  g
```

The bytes are stored "backwards" in memory. Always verify with GDB when dealing with multi-byte values.

### 3. Type Casting

**Confusion:**
> "What does (long)local_14 mean?"

**Concept:**

Type casting = telling the compiler to treat data as a different type.
```c
int x = 50;
long y = (long)x;  // x is still 50, just treated as 'long' type
```

The VALUE doesn't change - only the type representation.

### 4. The % (Modulo) Operator

**Modulo** = remainder after division
```
10 % 3 = 1   (10 ÷ 3 = 3 remainder 1)
26 % 26 = 0  (26 ÷ 26 = 1 remainder 0)
28 % 26 = 2  (28 ÷ 26 = 1 remainder 2)
-4 % 26 = 22 (in Python, handles negatives correctly)
```

**Use in Caesar cipher:**
Keeps values in range 0-25 (the 26 letters)

### 5. Bitwise Operations Quick Reference
```
&  (AND):   1 & 1 = 1,  1 & 0 = 0,  0 & 0 = 0
>> (shift): 1100 >> 1 = 0110  (shift bits right)
%  (mod):   Remainder after division
```

**Example:**
```
5 & 3:
  0101  (5 in binary)
& 0011  (3 in binary)
------
  0001  (1 in decimal)
```

### 6. x86-64 Calling Convention

**MEMORIZE THIS:**
```
Function(arg1, arg2, arg3, arg4, arg5, arg6)
         ↓     ↓     ↓     ↓     ↓     ↓
         RDI   RSI   RDX   RCX   R8    R9
```

**Examples:**
```c
strcmp(s1, s2)        →  RDI=s1, RSI=s2
memcmp(s1, s2, n)     →  RDI=s1, RSI=s2, RDX=n
printf(fmt, arg1)     →  RDI=fmt, RSI=arg1
```

### 7. Breakpoint Strategy

**Set breakpoints at:**

1. **Right BEFORE critical functions** (before memcmp, strcmp, etc.)
   - Allows you to inspect arguments
   
2. **Right AFTER input operations** (after scanf, fgets, read)
   - Verify input was read correctly
   
3. **Inside transformation loops** (but be careful - may break many times)
   - Observe incremental changes

**DON'T set breakpoints:**
- Randomly without a purpose
- At every line (information overload)

### 8. Forward vs Reverse Engineering

**Forward (brute force):**
```
Try: "aaaa" → scramble → compare (wrong)
Try: "aaab" → scramble → compare (wrong)
Try: "aaac" → scramble → compare (wrong)
... 26^50 possibilities = IMPOSSIBLE
```

**Reverse (mathematical):**
```
Target → unscramble → unscramble → unscramble → Password
```

**Always prefer reversal when possible!**

---

## The Complete Workflow Summary

### 1. Reconnaissance
```bash
file binary
checksec binary  
strings binary
./binary  # Test run
```

**Goal:** Understand what we're dealing with

### 2. Static Analysis (Ghidra)
- Load binary, auto-analyze
- Find `main` function
- Identify key operations:
  - Input functions (scanf, fgets, read)
  - Transformations (loops, math)
  - Comparisons (strcmp, memcmp, if statements)
  - Win conditions (success messages)

**Goal:** Understand program logic

### 3. Dynamic Analysis (GDB)
- Set strategic breakpoints (before comparisons)
- Run with test input
- Examine registers/memory
- Verify assumptions from static analysis

**Goal:** Get exact runtime values

### 4. Algorithm Analysis
- Understand transformation logic
- Identify if it's reversible
- Calculate computational complexity

**Goal:** Determine solving approach

### 5. Solution Development
- Write reversal script (if reversible)
- OR use brute force (if feasible)
- OR use side-channel attacks (if applicable)

**Goal:** Recover the password

### 6. Verification
- Test locally first
- Then test on remote server

**Goal:** Get the flag

---

## Essential GDB/pwndbg Commands

### Starting pwndbg
```bash
pwndbg ./binary
```

### Setting Breakpoints
```bash
break main                    # Break at function name
break *0x401234              # Break at address
break *main+100              # Break at offset from function
```

### Running
```bash
run                          # Start program
run < input.txt             # With input file
continue                    # Continue after breakpoint
```

### Examining Memory
```bash
x/s $rdi                    # Examine as string
x/20c $rsi                  # Examine 20 chars
x/20bx $rdi                 # Examine 20 bytes in hex
x/10gx $rsp                 # Examine 10 64-bit values (stack)
```

### Examining Registers
```bash
info registers              # All registers
info registers rdi rsi rdx  # Specific registers
print $rax                  # Print single register
```

### Stepping
```bash
si                          # Step one instruction
ni                          # Next instruction (skip calls)
finish                      # Run until function returns
```

### Other Useful Commands
```bash
vmmap                       # Show memory map
stack                       # Show stack
disassemble main            # Disassemble function
```

---

## Lessons Learned

### 1. Always Verify Static Analysis with Dynamic Analysis
- Ghidra may have confusing decompilation
- Hex values can be misread (endianness)
- GDB shows ground truth

### 2. Understand Memory Layout
- Stack variables are consecutive
- String operations don't care about variable names
- The `&` operator gives you the starting address

### 3. Pattern Recognition
- Nested loops over characters = transformation algorithm
- Multiple iterations = repeated application
- memcmp/strcmp = final check

### 4. Reversibility
- If transformation is mathematical and deterministic
- AND doesn't lose information
- THEN it's reversible

### 5. Tool Synergy
- **Ghidra:** Big picture understanding
- **GDB:** Precise runtime values
- **Python:** Implementation of solution
- Use ALL tools together!

---

## Common Mistakes to Avoid

### 1. ❌ Reading hex values directly from Ghidra
```c
local_68 = 0x676d76727970786c;
```
**Don't** try to convert this manually.
**Do** use GDB to see the actual string in memory.

### 2. ❌ Setting too many breakpoints
Don't break at every line - you'll drown in information.
Focus on critical points: input, transformations, comparisons.

### 3. ❌ Not verifying input was read correctly
Always check that scanf/fgets read your input as expected.
Break right after input operations.

### 4. ❌ Assuming you understand without testing
"I think this does X" → Test it in GDB!
Assumptions are often wrong.

### 5. ❌ Forgetting about multiple iterations
If the loop runs 3 times forward, reverse 3 times too.
Track iterations carefully.

---

## Practice Questions for Understanding

### Question 1: Memory Layout
If you have:
```c
int a = 0x41424344;
int b = 0x45464748;
```

And you call `strlen((char*)&a)`, what will it read?
<details>
<summary>Answer</summary>

It depends on endianness! On x86-64 (little-endian):
- Memory: `44 43 42 41 48 47 46 45`
- As string: "DCBAHGFE" (assuming no null bytes)

But these are not valid string characters (no null terminator), so it would keep reading until hitting a null byte in memory.
</details>

### Question 2: Calling Convention
A function is called with:
```assembly
mov rdi, 0x401000
mov rsi, 0x50
call some_function
```

What are the likely parameters?
<details>
<summary>Answer</summary>

Based on x86-64 calling convention:
- First parameter (RDI): 0x401000 (probably a pointer/address)
- Second parameter (RSI): 0x50 (probably a size/length = 80 in decimal)

Likely signature: `some_function(char *buffer, size_t length)`
</details>

### Question 3: Reversal Logic
If forward is: `y = (x + 5) % 26`

What is reverse?
<details>
<summary>Answer</summary>

Reverse: `x = (y - 5) % 26`

Example verification:
- Forward: x=2 → (2+5)%26 = 7
- Reverse: y=7 → (7-5)%26 = 2 ✓
</details>

---

## Additional Resources

### Learning Materials
- **GDB Tutorial:** https://www.gdbtutorial.com/
- **pwndbg Documentation:** https://github.com/pwndbg/pwndbg
- **Ghidra Documentation:** https://ghidra-sre.org/
- **x86-64 Reference:** https://www.felixcloutier.com/x86/

### Related CTF Challenges
- **picoCTF:** vault-door series (similar password checking)
- **pwnable.kr:** collision, bof (intro to reversing)
- **crackmes.one:** Beginner-friendly crackmes

### Tools Used
- **Ghidra** - Static analysis / decompiler
- **pwndbg** - Enhanced GDB for exploit development
- **Python 3** - Solution scripting
- **checksec** - Security analysis tool

---

## Final Thoughts

This challenge teaches:
1. **Systematic approach** to reverse engineering
2. **Tool combination** (static + dynamic analysis)
3. **Algorithm understanding** (transformation and reversal)
4. **Debugging skills** (setting breakpoints strategically)
5. **Memory concepts** (layout, endianness, pointers)

The key insight: **Don't try to understand everything at once.** Break down the problem:
- Reconnaissance → What is it?
- Static Analysis → What does it do?
- Dynamic Analysis → How does it actually work?
- Solution → How do I reverse it?

**Keep practicing, and these patterns will become second nature!**

---

## Flag
```
picoCTF{s0lv3_angry_symb0ls_150f8acd}
```
