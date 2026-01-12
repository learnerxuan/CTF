# its_not_functioning - CTF Reverse Engineering Writeup

## Challenge Overview
**Challenge Name:** its_not_functioning
**Category:** Reverse Engineering
**Binary:** reverse2 (Mach-O 64-bit ARM64 executable)

## Initial Analysis

First, I checked the file type and extracted strings from the binary:

```bash
$ file reverse2
reverse2: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>

$ strings reverse2 | grep -i flag
64%! '0!=0=<110;3942FLAG: %s
```

Interesting! There's an encoded string `64%! '0!=0=<110;3942` and a format string `FLAG: %s`. This suggests the flag is encoded somewhere in the binary.

## Function Discovery

Using pwndbg, I identified three key functions:

```
0x0000000100003dd4  decode
0x0000000100003e38  secret_function
0x0000000100003e90  main
```

## Reverse Engineering

### Main Function Analysis

The `main` function:
1. Prompts for a key with "Enter key: "
2. Reads user input (32 bytes)
3. Compares input against a hardcoded string
4. Prints "nope" or "Wrong key" depending on comparison
5. **Never calls `secret_function`!**

This is the trick - the main function is a red herring. The real flag is in the `secret_function` that never gets called during normal execution.

### Decode Function Analysis

Disassembling the `decode` function revealed a simple XOR cipher:

```asm
decode:
    ; Loop through string
    ldrb    w8, [x9]           ; Load byte
    mov     w10, #0x55         ; XOR key = 0x55
    eor     w8, w8, w10        ; XOR operation
    strb    w8, [x9]           ; Store decoded byte
    ; Continue loop
```

**Key insight:** Each byte is XORed with `0x55` to decode it.

### Secret Function Analysis

The `secret_function`:
1. Loads encoded data from address `0x100003f68` (20 bytes)
2. Calls `decode` to decrypt it
3. Prints "FLAG: %s" with the decoded string

## Flag Extraction

Using pwndbg, I read the encoded data from memory:

```bash
pwndbg> x/20xb 0x100003f68
0x100003f68: 0x36 0x34 0x25 0x21 0x20 0x27 0x30 0x21
0x100003f70: 0x3d 0x30 0x3d 0x3c 0x31 0x31 0x30 0x3b
0x100003f78: 0x33 0x39 0x34 0x32
```

### Decoding the Flag

I wrote a simple Python script to decode the flag:

```python
# Encoded flag data
encoded = bytes.fromhex('36342521202730213d303d3c3131303b33393432')

# Decode: XOR each byte with 0x55
decoded = bytes([b ^ 0x55 for b in encoded])

print("FLAG:", decoded.decode('ascii'))
```

Output:
```
FLAG: capturethehiddenflag
```

## Solution

The flag is: **capturethehiddenflag**

## Key Takeaways

1. **Hidden functionality:** The `secret_function` exists but is never called in normal program flow
2. **Simple crypto:** XOR with `0x55` is easily reversible
3. **Static analysis wins:** No need to find the correct "key" - just analyze the binary structure and decode the hardcoded flag
4. **Red herring:** The main function's key checking mechanism is intentionally misleading

## Tools Used
- **pwndbg** - Dynamic analysis and debugging
- **strings** - Quick reconnaissance
- **Python** - Decoding script

The challenge name "its_not_functioning" is a clever hint - the secret_function that contains the flag is not functioning (not being called) in the normal program execution!
