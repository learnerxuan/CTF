# The Illusionist's Bet - Reverse Engineering Writeup

**Challenge:** The Illusionist's Bet

**Category:** Reverse Engineering

**Flag:** `CYNX{4W_d@ngit_x1337_THE_HOUSE_ALWAYS_WINS}`

---

## Table of Contents
1. [Challenge Description](#challenge-description)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Binary Analysis with Ghidra](#binary-analysis-with-ghidra)
4. [Understanding the Crypto Functions](#understanding-the-crypto-functions)
5. [The Critical Discovery](#the-critical-discovery)
6. [Building the Solver](#building-the-solver)
7. [Solution and Flag](#solution-and-flag)
8. [Lessons Learned](#lessons-learned)

---

## Challenge Description

> Between the grey smoke and brown liquor lies a casino, the perfect place for a mirage to blend in. He floats between the smoke and flashes along the bright lights. Just as you arrive, you realize he has disappeared. Not without a trace, however, as you have his winning records. With this, you may be able to track his next location.
>
> **Flag Format:** `CYNX{r3ad4bl3Ch@r4c7eR5}`

**Files Provided:**
- `GambleCTF` - ELF 64-bit binary
- `M1r4g3_winnings_summary.txt` - Game log file

---

## Initial Reconnaissance

### File Analysis

Let's start by examining what we have:

```bash
$ file GambleCTF
GambleCTF: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=283f66bc560cbf4f8bc81591e97891b7edb4b44a,
for GNU/Linux 3.2.0, with debug_info, not stripped

$ checksec --file=GambleCTF
[*] '/path/to/GambleCTF'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

**Key observations:**
- Not stripped - excellent for analysis!
- Has debug info - even better!
- No stack canary - potential vulnerability (though not needed for this challenge)
- PIE enabled - addresses will be randomized at runtime

### Running the Binary

```bash
$ chmod +x GambleCTF
$ ./GambleCTF
Welcome to GambleCTF!
The world's first CTF where you can learn and gamble at the same time!
#By participating in this challenge PancakeSS is not responsible for any loss resulted.
Remember to always gamble responsibly.
Please enter your name: TestUser
Hello TestUser! Get ready to spin those reels!
You have 100 credits. Default bet: 10. Type 'h' for help.

Credits: 100 | Bet: 10 | Highscore: 1000
Commands: [Enter]=spin, b=change bet, a=autoplay, c=cash out
>
```

It's a slot machine game! Players can:
- Spin the reels
- Change bets
- Autoplay
- Cash out (creates a winnings summary file)

### Examining M1r4g3's Game Log

The provided file `M1r4g3_winnings_summary.txt` contains a complete game history:

```bash
$ wc -l M1r4g3_winnings_summary.txt
232 M1r4g3_winnings_summary.txt

$ head -30 M1r4g3_winnings_summary.txt
===============================================
           GambleCTF WINNINGS SUMMARY
===============================================
Session Date: Mon Sep 29 10:52:01 2025
===============================================

GAME STATISTICS:
Total Spins: 200
Final Credits: 3480
```

**Key observations:**
- Player name: "M1r4g3" (Mirage - an illusion!)
- 200 total spins recorded
- Final credits: 3,480 (well above the 1,000 highscore)

The most interesting part is **at the very end**:

```bash
$ tail -5 M1r4g3_winnings_summary.txt

===============================================
Remember The House Always Wins. OjhoIyW1OTvLZWkp2NWlOjhI0d6eCgWVQUhYDAPjiYZmQUGxaGS0V1oqm5m5SkFxAgSkiYW15eg4Skycm5xs0t
===============================================
```

**There's a suspicious base64-looking string after "Remember The House Always Wins."**

Let's try to decode it:

```bash
$ echo "OjhoIyW1OTvLZWkp2NWlOjhI0d6eCgWVQUhYDAPjiYZmQUGxaGS0V1oqm5m5SkFxAgSkiYW15eg4Skycm5xs0t" | base64 -d | xxd
00000000: 3a38 6823 25b5 393b cb65 6929 d8d5 a53a  :8h#%.9;.ei)...:
00000010: 3848 d1de 9e0a 0595 4148 580c 03e3 8986  8H......AHX.....
00000020: 6641 41b1 6864 b457 5a2a 9b99 b94a 4171  fAA.hd.WZ*...JAq
00000030: 0204 a489 85b5 e5e8 384a 4c9c 9b9c 6cd2  ........8JL...l.
00000040: 6261 7365 3634 3a20 696e 7661 6c69 6420  base64: invalid
00000050: 696e 7075 740a                           input.
```

Standard base64 decode fails! The binary data looks encrypted or encoded with a custom scheme.

**Initial hypothesis:** The string is somehow related to the flag, but we need to understand how the binary generates it.

---

## Binary Analysis with Ghidra

### Loading the Binary

Open Ghidra and create a new project, then import `GambleCTF`. Since it's not stripped, function names are preserved!

After auto-analysis completes, we can see several interesting custom functions:

```
xor_with_key
ror_bits
rol_bits
encrypted_name_to_string
apply_crypto_operation
create_winnings_summary
get_player_name
select_random_token
main
```

These names immediately suggest **cryptographic transformations**!

### Analyzing Main Function

The `main()` function shows the game flow:

```c
undefined8 main(void) {
    time_t tVar3;

    tVar3 = time((time_t *)0x0);
    srand((uint)tVar3);

    get_player_name();        // ← Get user's name
    select_random_token();    // ← Random selection (0-4)
    init_reel_weights();

    local_10 = get_highscore();
    printf("You have %ld credits. Default bet: %ld. Type 'h' for help.\n", credits, bet);

    // Game loop...
    // [spin mechanics, betting, etc.]

    create_winnings_summary();  // ← Generates the output file
    return 0;
}
```

### Understanding get_player_name()

```c
void get_player_name(void) {
    size_t sVar1;

    puts("Welcome to GambleCTF!");
    // [welcome messages...]
    printf("Please enter your name: ");

    fgets(player_name, 0x32, stdin);
    sVar1 = strlen(player_name);
    if ((sVar1 != 0) && ((&DAT_001062ff)[sVar1] == '\n')) {
        (&DAT_001062ff)[sVar1] = 0;  // Remove newline
    }

    strcpy(encrypted_name, player_name);  // ← COPY name to encrypted_name!
    sVar1 = strlen(player_name);
    original_name_length = (undefined4)sVar1;

    printf("\nHello %s! Get ready to spin those reels!\n", player_name);
    return;
}
```

**Key finding:** The player's name is copied to a buffer called `encrypted_name`. This buffer will be transformed!

### Understanding select_random_token()

```c
void select_random_token(void) {
    int iVar1;
    iVar1 = rand();
    active_token = iVar1 % 5;  // ← Select token 0-4
    return;
}
```

An "active_token" (0-4) is randomly selected. This will be important later.

---

## Understanding the Crypto Functions

### 1. xor_with_key() - XOR Cipher

```c
void xor_with_key(long param_1, char *param_2) {
    size_t sVar1;
    int local_c;

    sVar1 = strlen(param_2);
    for (local_c = 0; local_c < original_name_length; local_c = local_c + 1) {
        *(byte *)(param_1 + local_c) =
            *(byte *)(param_1 + local_c) ^ param_2[local_c % (int)sVar1];
    }
    return;
}
```

**What it does:** XOR encryption with a repeating key (Vigenère-style)

**Reversibility:** XOR is self-inverse: `A ⊕ B ⊕ B = A`

### 2. ror_bits() - Right Bit Rotation

```c
void ror_bits(long param_1, int param_2) {
    int local_354;
    byte abStack_348[400];
    byte abStack_1b8[408];
    int local_20;
    // [variable declarations...]

    if ((original_name_length != 0) && (param_2 != 0)) {
        local_20 = original_name_length * 8;
        local_354 = param_2 % local_20;

        // Convert bytes to bit array
        for (local_c = 0; local_c < original_name_length; local_c++) {
            for (local_10 = 0; local_10 < 8; local_10++) {
                abStack_1b8[local_10 + local_c * 8] =
                    (byte)((int)*(char *)(param_1 + local_c) >> (7U - (char)local_10)) & 1;
            }
        }

        // Rotate: output[i] = input[(i - shift) % total]
        for (local_14 = 0; local_14 < local_20; local_14++) {
            abStack_348[local_14] = abStack_1b8[((local_20 + local_14) - local_354) % local_20];
        }

        // Convert back to bytes
        for (local_18 = 0; local_18 < original_name_length; local_18++) {
            *(undefined *)(param_1 + local_18) = 0;
            for (local_1c = 0; local_1c < 8; local_1c++) {
                *(byte *)(param_1 + local_18) =
                    *(byte *)(param_1 + local_18) |
                    abStack_348[local_1c + local_18 * 8] << (7U - (char)local_1c);
            }
        }
    }
    return;
}
```

**What it does:** Treats the entire buffer as one long bit string and rotates it RIGHT

**Example:**
- Data: `[A][B][C]` = 24 bits total
- ROR 5: All bits shift right by 5 positions (circular)

**Reversibility:** `ROR(N)` is reversed by `ROL(N)`

### 3. rol_bits() - Left Bit Rotation

```c
void rol_bits(long param_1, int param_2) {
    // Very similar to ror_bits, but:
    // Rotate: output[i] = input[(shift + i) % total]
    abStack_348[local_14] = abStack_1b8[(local_354 + local_14) % local_20];
}
```

**What it does:** Rotates bits LEFT instead of RIGHT

**Reversibility:** `ROL(N)` is reversed by `ROR(N)`

### 4. encrypted_name_to_string() - Custom Encoding

This is the **critical function** that creates the output string:

```c
void encrypted_name_to_string(long param_1) {
    byte bVar2;
    int local_10;
    int local_c;

    local_c = 0;
    for (local_10 = 0; local_10 < original_name_length; local_10++) {
        bVar2 = encrypted_name[local_10];
        iVar1 = local_c + 1;

        // First character: low 6 bits
        *(char *)(local_c + param_1) =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[bVar2 & 0x3F];

        local_c = local_c + 2;

        // Second character: high 6 bits (shifted right 2)
        *(char *)(iVar1 + param_1) =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[bVar2 >> 2];
    }
    *(undefined *)(param_1 + local_c) = 0;
    return;
}
```

**⚠️ CRITICAL DISCOVERY: This is NOT standard base64!**

Each byte becomes **2 characters**:
- `char1 = alphabet[byte & 0x3F]` - Low 6 bits
- `char2 = alphabet[byte >> 2]` - High 6 bits

**Note:** Bits 5-2 appear in BOTH characters (overlapping encoding)!

**Output length:** `2 × input_length` (43 bytes → 86 characters)

To decode:
```python
low_6 = alphabet.index(char1)   # bits [5:0]
high_6 = alphabet.index(char2)  # bits [7:2] in positions [5:0]
byte = (high_6 << 2) | (low_6 & 0x03)
```

### 5. apply_crypto_operation() - The Routing Logic

```c
void apply_crypto_operation(char *param_1, uint param_2) {
    int iVar1;

    iVar1 = strcmp(param_1, "NO WIN");
    if (iVar1 == 0) {
        xor_with_key(encrypted_name, jackpot_key);
    }
    else {
        iVar1 = strcmp(param_1, "TWO MATCH");
        if (iVar1 == 0) {
            ror_bits(encrypted_name,
                *(undefined4 *)(CRYPTO_MAPPINGS + ((ulong)active_token * 7 + (ulong)param_2) * 4));
            jackpot_key[0] = 'D';
            jackpot_key[1] = 'a';
            jackpot_key[2] = 'n';
            jackpot_key[3] = 't';
            jackpot_key[4] = 'e';
            jackpot_key[5] = '\0';  // "Dante"
        }
        else {
            iVar1 = strcmp(param_1, "THREE MATCH");
            if (iVar1 == 0) {
                rol_bits(encrypted_name,
                    *(undefined4 *)(CRYPTO_MAPPINGS + ((ulong)active_token * 7 + (ulong)param_2) * 4));
                jackpot_key[0] = 'V';
                jackpot_key[1] = 'i';
                jackpot_key[2] = 'r';
                jackpot_key[3] = 'g';
                jackpot_key[4] = 'i';
                jackpot_key[5] = 'l';
                jackpot_key[6] = '\0';  // "Virgil"
            }
        }
    }
    return;
}
```

**The transformation rules:**
- **"NO WIN"**: XOR with current `jackpot_key`
- **"TWO MATCH"**: ROR by N bits, then set `jackpot_key = "Dante"`
- **"THREE MATCH"**: ROL by N bits, then set `jackpot_key = "Virgil"`

The rotation amount comes from `CRYPTO_MAPPINGS[active_token][symbol_index]`.

### Finding CRYPTO_MAPPINGS Table

Using Ghidra, navigate to the `.data` section around address `0x60e0`:

```
Hex dump of section '.data':
  0x000060e0 07000000 11000000 1b000000 25000000  # Token 0
  0x000060f0 2f000000 39000000 09030000 05000000
  0x00006100 0f000000 19000000 23000000 2d000000  # Token 1
  0x00006110 32000000 2b020000 02000000 0c000000
  0x00006120 16000000 20000000 2a000000 34000000  # Token 2
  0x00006130 de000000 09030000 09030000 09030000
  0x00006140 09030000 09030000 09030000 09030000  # Token 3
  0x00006150 7b000000 f5000000 a6020000 db030000
  0x00006160 3e020000 d7030000 0c030000            # Token 4
```

Converting to decimal and organizing by symbols (CHERRY, LEMON, ORANGE, PLUM, BELL, STAR, SEVEN):

```
         CHERRY  LEMON  ORANGE  PLUM  BELL  STAR  SEVEN
Token 0:    7     17     27     37    47    57    777
Token 1:    5     15     25     35    45    50    555
Token 2:    2     12     22     32    42    52    222
Token 3:  777    777    777    777   777   777    777
Token 4:  123    245    678    987   574   983    780
```

---

## The Critical Discovery

### Question: When are crypto operations applied?

Looking at the `evaluate()` function (called after each spin):

```c
long evaluate(uint *param_1, long param_2) {
    // [calculate wins, payouts, etc.]

    if (local_10 == 0) {
        puts("No winning combinations. Better luck next spin.");
    }

    // ← HERE IS THE CRITICAL LINE:
    if (total_spins < 0xb) {
        apply_crypto_operation(&local_58, local_14);
    }

    add_spin_to_history(param_1, local_10, &local_58, local_14);
    return local_10;
}
```

**🚨 CRITICAL FINDING:**

```c
if (total_spins < 0xb) {  // 0xb = 11 in decimal
    apply_crypto_operation(&local_58, local_14);
}
```

**Only the first 10 spins apply crypto operations!** (spins 1-10, since `total_spins` is incremented before `evaluate()` is called)

### Initial Confusion

**My initial mistake:** I thought all 200 spins transformed the name!

**Reality:** Only the first 10 outcomes matter. The remaining 190 spins are just for gameplay and don't affect the crypto state.

### Verifying with M1r4g3's First 10 Spins

Let's extract the first 10 outcomes from the game log:

```bash
$ grep -E '^\s+[0-9]+ \|' M1r4g3_winnings_summary.txt | head -10
    1 | CHERRY  STAR    LEMON   | NO WIN           | -       |     0 |    1990
    2 | CHERRY  LEMON   CHERRY  | TWO MATCH        | CHERRY  |    20 |    1980
    3 | CHERRY  LEMON   LEMON   | TWO MATCH        | LEMON   |    10 |    1990
    4 | PLUM    PLUM    PLUM    | THREE MATCH      | PLUM    |   200 |    1990
    5 | LEMON   LEMON   CHERRY  | TWO MATCH        | LEMON   |    10 |    2180
    6 | ORANGE  CHERRY  LEMON   | NO WIN           | -       |     0 |    2180
    7 | LEMON   CHERRY  LEMON   | TWO MATCH        | LEMON   |    10 |    2170
    8 | PLUM    CHERRY  LEMON   | NO WIN           | -       |     0 |    2170
    9 | LEMON   BELL    LEMON   | TWO MATCH        | LEMON   |    10 |    2160
   10 | LEMON   LEMON   LEMON   | THREE MATCH      | LEMON   |    80 |    2160
```

**Summary:**
1. NO WIN
2. TWO MATCH (CHERRY)
3. TWO MATCH (LEMON)
4. THREE MATCH (PLUM)
5. TWO MATCH (LEMON)
6. NO WIN
7. TWO MATCH (LEMON)
8. NO WIN
9. TWO MATCH (LEMON)
10. THREE MATCH (LEMON)

These 10 operations transformed the original name into the final encrypted state!

---

## Building the Solver

### Solver Strategy

Since all operations are reversible, we can:

1. **Decode** the custom base64 string to get final `encrypted_name` bytes
2. **For each token (0-4):**
   - Process the 10 spins in **reverse order** (spin 10 → spin 1)
   - Apply the inverse operation:
     - THREE MATCH → Reverse with ROR
     - TWO MATCH → Reverse with ROL
     - NO WIN → XOR again (self-inverse)
3. **Check** if the result is a valid flag

### Python Solver Implementation

```python
#!/usr/bin/env python3
"""
GambleCTF Solver - Reverse crypto transformations
"""

import re
from typing import List, Dict

BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

CRYPTO_MAPPINGS = [
    [7, 17, 27, 37, 47, 57, 777],      # Token 0
    [5, 15, 25, 35, 45, 50, 555],      # Token 1
    [2, 12, 22, 32, 42, 52, 222],      # Token 2
    [777, 777, 777, 777, 777, 777, 777],  # Token 3
    [123, 245, 678, 987, 574, 983, 780]   # Token 4
]

SYMBOL_MAP = {
    "CHERRY": 0, "LEMON": 1, "ORANGE": 2, "PLUM": 3,
    "BELL": 4, "STAR": 5, "SEVEN": 6
}

def decode_custom_base64(encoded: str) -> bytes:
    """Decode the custom base64-like encoding"""
    decoded = bytearray()
    for i in range(0, len(encoded), 2):
        if i + 1 >= len(encoded):
            break
        char1 = encoded[i]
        char2 = encoded[i + 1]
        low_6 = BASE64_ALPHABET.index(char1)
        high_6 = BASE64_ALPHABET.index(char2)
        # Reconstruct: high 6 bits from char2, low 2 bits from char1
        byte_val = (high_6 << 2) | (low_6 & 0x03)
        decoded.append(byte_val)
    return bytes(decoded)

def ror_bits(data: bytes, bits: int) -> bytes:
    """Rotate bits RIGHT - treats entire buffer as one bit string"""
    if len(data) == 0 or bits == 0:
        return data

    # Convert bytes to bit array
    bit_array = []
    for byte in data:
        for i in range(8):
            bit_array.append((byte >> (7 - i)) & 1)

    total_bits = len(data) * 8
    bits = bits % total_bits
    if bits == 0:
        return data

    # Rotate: new[i] = old[(i - bits) % total]
    rotated = [bit_array[(i - bits) % total_bits] for i in range(total_bits)]

    # Convert back to bytes
    result = bytearray()
    for i in range(0, len(rotated), 8):
        byte_val = 0
        for j in range(8):
            byte_val |= rotated[i + j] << (7 - j)
        result.append(byte_val)

    return bytes(result)

def rol_bits(data: bytes, bits: int) -> bytes:
    """Rotate bits LEFT"""
    if len(data) == 0 or bits == 0:
        return data

    bit_array = []
    for byte in data:
        for i in range(8):
            bit_array.append((byte >> (7 - i)) & 1)

    total_bits = len(data) * 8
    bits = bits % total_bits
    if bits == 0:
        return data

    # Rotate: new[i] = old[(i + bits) % total]
    rotated = [bit_array[(i + bits) % total_bits] for i in range(total_bits)]

    result = bytearray()
    for i in range(0, len(rotated), 8):
        byte_val = 0
        for j in range(8):
            byte_val |= rotated[i + j] << (7 - j)
        result.append(byte_val)

    return bytes(result)

def xor_with_key(data: bytes, key: bytes) -> bytes:
    """XOR data with repeating key"""
    if len(key) == 0:
        return data
    result = bytearray()
    key_len = len(key)
    for i, byte in enumerate(data):
        result.append(byte ^ key[i % key_len])
    return bytes(result)

def parse_spin_history(filename: str) -> List[Dict]:
    """Parse M1r4g3_winnings_summary.txt to extract spin operations"""
    spins = []
    with open(filename, 'r') as f:
        for line in f:
            match = re.match(
                r'\s+(\d+)\s+\|.*\|\s+(NO WIN|TWO MATCH|THREE MATCH)\s+\|\s+(\S+)\s+\|',
                line
            )
            if match:
                spin_num = int(match.group(1))
                outcome = match.group(2)
                symbol = match.group(3) if outcome != "NO WIN" else None
                spins.append({
                    "spin": spin_num,
                    "outcome": outcome,
                    "symbol": symbol
                })
    return spins

def simulate_key_changes(spins: List[Dict]) -> List[bytes]:
    """Simulate jackpot_key changes to know key at each step"""
    keys = []
    current_key = b"Jackpot"  # Initial key from binary analysis

    for spin in spins:
        keys.append(current_key)
        # Key changes AFTER the operation
        if spin["outcome"] == "TWO MATCH":
            current_key = b"Dante"
        elif spin["outcome"] == "THREE MATCH":
            current_key = b"Virgil"

    return keys

def reverse_transform(encrypted_data: bytes, spins: List[Dict], token: int) -> bytes:
    """Reverse transformations for a given token"""
    data = bytearray(encrypted_data)

    # Only first 10 spins apply crypto
    crypto_spins = spins[:10]

    # Get keys for each spin
    keys = simulate_key_changes(crypto_spins)

    # Process in REVERSE order (spin 10 -> 1)
    for i in range(len(crypto_spins) - 1, -1, -1):
        spin = crypto_spins[i]
        outcome = spin["outcome"]
        symbol = spin["symbol"]
        key_at_spin = keys[i]

        if outcome == "THREE MATCH":
            # Forward: ROL, Reverse: ROR
            symbol_idx = SYMBOL_MAP[symbol]
            bits = CRYPTO_MAPPINGS[token][symbol_idx]
            data = ror_bits(bytes(data), bits)

        elif outcome == "TWO MATCH":
            # Forward: ROR, Reverse: ROL
            symbol_idx = SYMBOL_MAP[symbol]
            bits = CRYPTO_MAPPINGS[token][symbol_idx]
            data = rol_bits(bytes(data), bits)

        elif outcome == "NO WIN":
            # XOR is self-inverse
            data = xor_with_key(bytes(data), key_at_spin)

    return bytes(data)

def main():
    encoded_string = "OjhoIyW1OTvLZWkp2NWlOjhI0d6eCgWVQUhYDAPjiYZmQUGxaGS0V1oqm5m5SkFxAgSkiYW15eg4Skycm5xs0t"

    print("[*] Decoding custom base64...")
    encrypted_data = decode_custom_base64(encoded_string)
    print(f"    Decoded: {len(encrypted_data)} bytes")

    print("\n[*] Parsing spin history...")
    spins = parse_spin_history("M1r4g3_winnings_summary.txt")
    print(f"    Total spins: {len(spins)}")
    print(f"    Crypto spins (first 10): {len(spins[:10])}")

    print("\n[*] Trying all 5 tokens...")
    for token in range(5):
        print(f"\n    Token {token}:")
        try:
            result = reverse_transform(encrypted_data, spins, token)
            text = result.decode('ascii', errors='replace')
            print(f"        Result: {text}")

            if 'CYNX{' in text and '}' in text:
                print(f"\n{'='*60}")
                print(f"🎰 FLAG FOUND: {text}")
                print('='*60)
                return text
        except Exception as e:
            print(f"        Error: {e}")

if __name__ == "__main__":
    main()
```

### Running the Solver

```bash
$ python3 solver.py
[*] Decoding custom base64...
    Decoded: 43 bytes

[*] Parsing spin history...
    Total spins: 200
    Crypto spins (first 10): 10

[*] Trying all 5 tokens...

    Token 0:
        Result: I-E��DfX��v~8��1_p��HeD��\D[��^oG��{WA����

    Token 1:
        Result: *���(9���(8���_q���...

    Token 2:
        Result: CYNX{4W_d@ngit_x1337_THE_HOUSE_ALWAYS_WINS}

============================================================
🎰 FLAG FOUND: CYNX{4W_d@ngit_x1337_THE_HOUSE_ALWAYS_WINS}
============================================================
```

---

## Solution and Flag

### Answer

```
CYNX{4W_d@ngit_x1337_THE_HOUSE_ALWAYS_WINS}
```

### How it Works

1. **Original name entered:** `CYNX{4W_d@ngit_x1337_THE_HOUSE_ALWAYS_WINS}`
2. **Token selected:** 2 (random at game start)
3. **First 10 spins transformed the name:**
   - Spin 1: NO WIN → XOR with "Jackpot"
   - Spin 2: TWO MATCH (CHERRY) → ROR 2 bits, key="Dante"
   - Spin 3: TWO MATCH (LEMON) → ROR 12 bits, key="Dante"
   - Spin 4: THREE MATCH (PLUM) → ROL 32 bits, key="Virgil"
   - Spin 5: TWO MATCH (LEMON) → ROR 12 bits, key="Dante"
   - Spin 6: NO WIN → XOR with "Dante"
   - Spin 7: TWO MATCH (LEMON) → ROR 12 bits, key="Dante"
   - Spin 8: NO WIN → XOR with "Dante"
   - Spin 9: TWO MATCH (LEMON) → ROR 12 bits, key="Dante"
   - Spin 10: THREE MATCH (LEMON) → ROL 12 bits, key="Virgil"
4. **Final encrypted_name → Custom base64 encoding → Written to file**
5. **We reversed all 10 operations to recover the original name**

### The Mirage

The challenge title "The Illusionist's Bet" and the username "M1r4g3" (Mirage) were hints:
- **M1r4g3 is a fake identity** - an illusion!
- The **real location/identity** was hidden cryptographically
- The message "**THE_HOUSE_ALWAYS_WINS**" in the flag ties perfectly to the casino theme
- The closing line "Remember The House Always Wins" was a double hint pointing to the flag content

---

## Lessons Learned

### 1. Always Read the Assembly Carefully

The condition `if (total_spins < 0xb)` was easy to miss during initial analysis. This single line changed everything - from thinking we needed to reverse 200 operations to realizing only 10 mattered.

**Takeaway:** Don't make assumptions. Verify every detail in the code.

### 2. Custom Encoding Schemes

The "base64-like" encoding was **not** standard base64. Each byte → 2 characters with overlapping bits.

**Takeaway:** Test decoders with known values before trusting them. I validated mine with:

```python
test = b"CYNX{test}"
encoded = encode_custom_base64(test)
decoded = decode_custom_base64(encoded)
assert decoded == test  # ✓
```

### 3. Reversibility Analysis

Recognizing that all operations were reversible was key:
- **XOR:** Self-inverse
- **ROL/ROR:** Inverse of each other
- **Composition:** Can be undone in reverse order

**Takeaway:** In crypto challenges, always check if operations are reversible before trying to break encryption.

### 4. State Machine Understanding

The `jackpot_key` changed based on outcomes:
- Starts as "Jackpot"
- Changes to "Dante" after TWO MATCH
- Changes to "Virgil" after THREE MATCH
- Persists until next match

**Takeaway:** Track state changes carefully. I simulated forward to know which key was active for each NO WIN operation.

### 5. Brute Force When Needed

With only 5 possible tokens, trying all of them was faster than trying to figure out which was used.

**Takeaway:** Sometimes the simplest solution is the best. 5 iterations is nothing for a computer.

---

## Quick Reference Commands

```bash
# File analysis
file GambleCTF
checksec --file=GambleCTF
strings GambleCTF | less

# Run binary
./GambleCTF

# Examine data file
head M1r4g3_winnings_summary.txt
tail M1r4g3_winnings_summary.txt
grep -E '^\s+[0-9]+ \|' M1r4g3_winnings_summary.txt | head -10

# Ghidra analysis
# 1. Load binary in Ghidra
# 2. Auto-analyze
# 3. Find functions: xor_with_key, ror_bits, rol_bits, encrypted_name_to_string
# 4. Examine .data section for CRYPTO_MAPPINGS table
# 5. Check evaluate() for crypto operation constraint

# Run solver
python3 solver.py
```

---

**Challenge Rating:** ⭐⭐⭐⭐ (4/5)
**Time Spent:** ~2-3 hours
**Key Skills:** Reverse engineering, cryptography, Python scripting, Ghidra

Thanks for the fun challenge! The narrative tie-in with the "mirage" theme and the "HOUSE_ALWAYS_WINS" message was excellent. 🎰
