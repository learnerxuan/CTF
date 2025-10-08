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
```bash
$ checksec main
[*] '/path/to/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

Protection Summary:

✅ No Stack Canary: Buffer overflow won't be detected
✅ No PIE: Code addresses are fixed (no randomization)
❌ NX Enabled: Stack is non-executable (can't inject shellcode)

Conclusion: Classic ret2win challenge - overflow buffer to redirect execution to win().
File Information
$ file main
main: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ ls -la
-rw-rw-r-- 1 user user    17 Sep  1 01:08 flag.txt
-rwxrwxr-x 1 user user 16240 Sep  1 00:37 main
