# zip++ - Securinets CTF 2024 Writeup

**Category:** PWN (Binary Exploitation)  
**Difficulty:** Medium  
**Files Provided:** main, flag.txt  
**Connection:** `nc pwn-14caf623.p1.securinets.tn 9000`

## Table of Contents

- [Challenge Description](#challenge-description)
- [Initial Analysis](#initial-analysis)
- [Understanding Buffer Overflows - Beginner's Guide](#understanding-buffer-overflows---beginners-guide)
- [Reverse Engineering](#reverse-engineering)
- [RLE Compression Deep Dive](#rle-compression-deep-dive)
- [Vulnerability Analysis](#vulnerability-analysis)
- [Stack Layout Explained](#stack-layout-explained)
- [Understanding Return Addresses - Beginner Questions](#understanding-return-addresses---beginner-questions)
- [The Stack Alignment Problem](#the-stack-alignment-problem)
- [Exploitation Strategy](#exploitation-strategy)
- [Complete Exploit](#complete-exploit)
- [Key Takeaways](#key-takeaways)

---

## Challenge Description

> why isn't my compressor compressing ?!

The challenge provides a binary implementing Run-Length Encoding (RLE) compression. The program reads user input, compresses it, and prints the result. Our goal is to exploit a buffer overflow in the compression function to execute a hidden `win()` function that prints the flag.

---

## Initial Analysis

### Binary Protections

Check security features:
```bash$ checksec main
[*] '/path/to/main'
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

**Protection Summary:**
- ✅ **No Stack Canary:** Buffer overflow won't be detected
- ✅ **No PIE:** Code addresses are fixed (no randomization)
- ❌ **NX Enabled:** Stack is non-executable (can't inject shellcode)

**Conclusion:** Classic **ret2win** challenge - overflow buffer to redirect execution to `win()`.

### File Information
```bash$ file main
main: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped$ ls -la
-rw-rw-r-- 1 user user    17 Sep  1 01:08 flag.txt
-rwxrwxr-x 1 user user 16240 Sep  1 00:37 main

### Program Behavior
```bash$ ./main
data to compress :
AAAA
compressed data  : 4104
data to compress :
ABAB
compressed data  : 41014201
data to compress :
exit
bye

**Program Flow:**
1. Prompts for input data
2. Compresses using RLE
3. Prints compressed result in hex
4. Loops until "exit"
5. Prints "bye" and exits

### Key Functions
```bash$ objdump -t main | grep -E 'main|vuln|win|compress'
0000000000401381 g     F .text  000000000000002e main
000000000040126b g     F .text  0000000000000116 vuln
00000000004011a5 g     F .text  0000000000000016 win
00000000004011bb g     F .text  00000000000000b0 compress

**Important Functions:**
1. `main()` at `0x401381` - Entry point
2. `vuln()` at `0x40126b` - Contains vulnerability
3. `win()` at `0x4011a5` - Target function (prints flag)
4. `compress()` at `0x4011bb` - RLE implementation

---

## Understanding Buffer Overflows - Beginner's Guide

### What is a Buffer Overflow?

Writing more data to a buffer than it can hold, causing data to spill into adjacent memory.

**Simple Example:**
```cchar buffer[10];           // 10 bytes
strcpy(buffer, "Hello");   // OK: 6 bytes
strcpy(buffer, "This is way too long!");  // OVERFLOW: 22 bytes!

**Memory Layout:**Before overflow:
[buffer: 10 bytes] [other data] [return address]After overflow:
[buffer: overwritten] [overwritten!] [OVERWRITTEN!]
↑
We control this!
