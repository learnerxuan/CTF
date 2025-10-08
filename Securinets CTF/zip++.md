zip++ - Securinets CTF 2024 WriteupCategory: PWN (Binary Exploitation)
Difficulty: Medium
Files Provided: main, flag.txt
Connection: nc pwn-14caf623.p1.securinets.tn 9000Table of Contents
Challenge Description
Initial Analysis
Understanding Buffer Overflows - Beginner's Guide
Reverse Engineering
RLE Compression Deep Dive
Vulnerability Analysis
Stack Layout Explained
Understanding Return Addresses
The Stack Alignment Problem
Exploitation Strategy
Complete Exploit
Beginner Questions Answered
Key Takeaways
Challenge Description
why isn't my compressor compressing ?!
The challenge provides a binary implementing Run-Length Encoding (RLE) compression. The program reads user input, compresses it, and prints the result. Our goal is to exploit a buffer overflow in the compression function to execute a hidden win() function that prints the flag.Initial AnalysisBinary ProtectionsCheck security features:bash$ checksec main
[*] '/path/to/main'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)Protection Summary:

✅ No Stack Canary: Buffer overflow won't be detected
✅ No PIE: Code addresses are fixed (no randomization)
❌ NX Enabled: Stack is non-executable (can't inject shellcode)
Conclusion: Classic ret2win challenge - overflow buffer to redirect execution to win().
