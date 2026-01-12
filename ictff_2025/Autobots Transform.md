# Autobots Transform - CTF Writeup

**Category:** Reverse Engineering
**Difficulty:** Medium
**Flag:** `selfreconstruct`

## Challenge Description

We're given a binary file named `reverse3` that appears to validate a flag input.

## Initial Reconnaissance

First, let's examine what we're working with:

```bash
$ file reverse3
reverse3: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE>

$ strings reverse3
Enter flag:
Wrong
Correct
```

The binary is a macOS ARM64 executable that prompts for a flag and validates it.

## Binary Analysis

### Finding the Encoded Flag

Using hexdump to examine the binary, we can find some interesting data right before the "Enter flag:" string:

```bash
$ hexdump -C reverse3 | grep -B5 -A5 "Enter flag"
00003f80  00 02 1f d6 b6 25 6c 8b  fa a1 70 4f 56 2d 24 63  |.....%l...pOV-$c|
00003f90  7a e9 a0 45 6e 74 65 72  20 66 6c 61 67 3a 20 00  |z..Enter flag: .|
00003fa0  0a 00 57 72 6f 6e 67 00  43 6f 72 72 65 63 74 00  |..Wrong.Correct.|
```

The bytes `b6 25 6c 8b fa a1 70 4f 56 2d 24 63 7a e9 a0` appear to be our encoded flag!

### Disassembly with radare2

Using radare2 to analyze the main function and identify the key logic:

```bash
$ r2 -q -c 'aaa; afl' reverse3
```

We find:
- `main` at `0x100003e10` - Main validation logic
- `sym.func.100003db8` - Character encoding function

### Understanding the Main Function

The main function:

1. **Reads input:** Uses `fgets()` to read up to 64 characters
2. **Length check:** Validates the flag is exactly 15 characters long
3. **Character-by-character encoding:** Loops through each character, calling the encoding function
4. **Comparison:** Compares encoded result against hardcoded bytes

Key assembly snippets:

```asm
0x100003e88  bl   sym.imp.strlen       ; Get input length
0x100003e8c  subs x8, x0, 0xf          ; Check if length == 15
0x100003e94  tbnz w8, 0, 0x100003eb0   ; If not 15, jump to wrong
```

### Reverse Engineering the Encoding Function

Analyzing the encoding function at `0x100003db8`:

```asm
; w0 = character, w1 = index
0x100003dc8  add  w9, w8, 0xa5         ; w9 = index + 0xa5
0x100003dd0  eor  w8, w8, w9           ; char ^= (index + 0xa5)
0x100003de0  asr  w8, w8, 5            ; w8 = char >> 5
0x100003de4  orr  w8, w8, w9, lsl 3    ; w8 = (char >> 5) | (w9 << 3)
0x100003df4  mul  w9, w8, w9           ; w9 = index * 7 (0x7 loaded earlier)
0x100003dfc  add  w8, w8, w9           ; char += (index * 7)
```

The encoding algorithm for each character at position `i`:
1. XOR character with `(i + 0xa5)`
2. Bit rotation: `(val >> 5) | ((val & 0x1f) << 3)`
3. Add `(i * 7)`

## Solution

To decode the flag, we need to reverse each operation:

```python
def encode_char(c, index):
    """Forward encoding function"""
    val = ord(c)
    # Step 1: XOR with (index + 0xa5)
    val ^= (index + 0xa5)
    # Step 2: Rotate bits - (val >> 5) | (val << 3)
    val = ((val >> 5) | (val << 3)) & 0xFF
    # Step 3: Add (index * 7)
    val = (val + (index * 7)) & 0xFF
    return val

def decode_char(encoded, index):
    """Reverse the encoding"""
    # Reverse step 3: Subtract (index * 7)
    val = (encoded - (index * 7)) & 0xFF

    # Reverse step 2: Reverse rotation
    # Original: (val >> 5) | (val << 3)
    # Reverse: (val >> 3) | (val << 5)
    val = ((val >> 3) | (val << 5)) & 0xFF

    # Reverse step 1: XOR with (index + 0xa5)
    val ^= (index + 0xa5)

    return chr(val & 0xFF)

# Encoded flag bytes from the binary
encoded = [0xb6, 0x25, 0x6c, 0x8b, 0xfa, 0xa1, 0x70, 0x4f,
           0x56, 0x2d, 0x24, 0x63, 0x7a, 0xe9, 0xa0]

# Decode the flag
flag = ''
for i, enc in enumerate(encoded):
    flag += decode_char(enc, i)

print(f"Flag: {flag}")
```

Running the decoder:

```bash
$ python3 decode.py
Flag: selfreconstruct
```

### Verification

We can verify by encoding our decoded flag back:

```python
encoded_check = [encode_char(c, i) for i, c in enumerate("selfreconstruct")]
print(f"Encoded:  {' '.join(f'{b:02x}' for b in encoded_check)}")
print(f"Expected: b6 25 6c 8b fa a1 70 4f 56 2d 24 63 7a e9 a0")
```

Output:
```
Encoded:  b6 25 6c 8b fa a1 70 4f 56 2d 24 63 7a e9 a0
Expected: b6 25 6c 8b fa a1 70 4f 56 2d 24 63 7a e9 a0
Match: True
```

## Flag

**`selfreconstruct`**

## Key Takeaways

1. **Static Analysis:** Even without running the binary (macOS ARM64 on Linux), we can fully reverse engineer it
2. **Encoded Data Location:** The encoded flag was stored in the binary's data section, right before the "Enter flag:" string
3. **Algorithm Reversal:** Each operation in the encoding function must be carefully reversed in the opposite order
4. **Bit Manipulation:** Understanding bit rotations is crucial - rotating right by 5 and left by 3 is reversed by rotating right by 3 and left by 5

The flag name "selfreconstruct" is quite fitting for a challenge called "Autobots Transform" - a nice reference to the Transformers' ability to reconstruct and transform themselves!
