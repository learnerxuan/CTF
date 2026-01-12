# Ramadhan Challenge Writeup

## Challenge Information
- **Name:** 38 hari menjelang Ramadhan
- **Category:** Reverse Engineering / Pwn
- **Binary:** Ramadhan (ARM64 macOS Mach-O)

## Overview
This challenge presents a simple password verification program that reveals a flag when the correct passcode is entered.

## Initial Analysis

### File Information
```bash
$ file Ramadhan
Ramadhan: Mach-O 64-bit executable arm64
```

The binary is an ARM64 macOS executable, so it cannot be executed directly on Linux systems.

### Binary Structure
```bash
$ strings Ramadhan | head -20
```

From the strings output, we can identify several key components:
- Password prompt: `"Please enter the passcode (6 Digits): "`
- Hardcoded password: `"763451"`
- A long religious text (hadith) about Ramadan
- The flag embedded within the text

## Reverse Engineering

### Main Function Analysis

Looking at the disassembly of the main function:

```assembly
main+40:  bl   printf          ; "Please enter the passcode (6 Digits): "
main+68:  bl   scanf           ; Read user input
main+84:  bl   strcmp          ; Compare input with "763451"
main+88:  subs w8, w0, #0x0   ; Check if strcmp returned 0
main+92:  cset w8, ne         ; Set flag if not equal
main+96:  tbnz w8, #0, 0x100002f7c  ; Jump to failure path if wrong password
```

**Key Observations:**
1. The program uses `strcmp` to compare user input with the hardcoded password `"763451"`
2. If the comparison succeeds (returns 0), the program continues to the success path
3. If the comparison fails, it jumps to address `main+192` (failure path)

### Success Path

When the correct password is entered, the program executes:

```assembly
main+104: bl   printf   ; Print string at 0x100003019
main+112: bl   printf   ; Print string at 0x10000318f
main+124: bl   printf   ; Print string at 0x100003327
main+136: bl   printf   ; Print string at 0x1000034a6
```

These four `printf` calls output a long hadith (Islamic religious text) about Ramadan.

### Finding the Flag

Using strings and grep to locate the flag:

```bash
$ strings Ramadhan | grep "ictff"
Bila masuk Subuh dia pergi ke masjid dan dia bagitahu kepada semua sahabat,
sahabat Nabi, apa yang dia tengak di dalam mimpi. ictff8{Ramadhan yang mulia}
Kesemua sahabat...
```

### Hexdump Verification

To verify the exact flag format and spelling:

```bash
$ hexdump -C Ramadhan | grep -A2 -B2 "ictff8"
000038b0  61 6d 20 6d 69 6d 70 69  2e 20 69 63 74 66 66 38  |am mimpi. ictff8|
000038c0  7b 52 61 6d 61 64 68 61  6e 20 79 61 6e 67 20 6d  |{Ramadhan yang m|
000038d0  75 6c 69 61 7d 20 4b 65  73 65 6d 75 61 20 73 61  |ulia} Kesemua sa|
```

## Solution

### Method 1: Static Analysis (Used)
Since we cannot run the ARM64 macOS binary on Linux, we extract the flag through static analysis:

1. Use `strings` to dump all readable strings from the binary
2. Search for the flag format pattern `ictff*{*}`
3. Extract the complete flag

```bash
$ strings Ramadhan | grep -E "ictff.*\{.*\}"
...ictff8{Ramadhan yang mulia}...
```

### Method 2: Running the Binary (Alternative)
If running on macOS ARM64 or using an emulator:

```bash
$ ./Ramadhan
Please enter the passcode (6 Digits): 763451
[Full hadith text with flag]
```

## Flag

```
ictff8{Ramadhan yang mulia}
```

**Translation:** "The noble Ramadan" (Malay language)

## Key Takeaways

1. **String Analysis is Powerful:** Even without running the binary, we can extract critical information through string analysis
2. **Password Verification:** Simple strcmp-based password checks can be easily bypassed through static analysis
3. **Cross-Platform Challenges:** ARM64 macOS binaries require different analysis techniques on Linux systems
4. **Cultural Context:** The challenge incorporates religious text about Ramadan, making the flag meaningful in context

## Tools Used
- `strings` - Extract printable strings from binary
- `hexdump` - Verify exact byte sequences
- `grep` - Search for patterns
- `file` - Identify binary format
- pwndbg (via MCP) - Disassembly and memory examination
