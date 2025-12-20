# SECCON CTF 2025 - Breaking Out Challenge Writeup

## Challenge Overview

**Name:** Breaking Out  
**Category:** Reverse Engineering / Web  
**Files:** `index.html`, `game.js` (113KB obfuscated JavaScript)  
**Objective:** Extract flag from a Phaser.js breakout game by decrypting 100 nested levels  
**Flag:** `SECCON{H4ve_y0u_3ver_p14yed_Atari?_SQiOIVX6HPtRekE1vTn4}`

**Challenge Concept:**  
A browser-based Breakout game where the flag is hidden inside 100 levels of nested encryption. Each level is encrypted with RC4 using a key derived from that level's brick values. The final level (99) contains a QR code in ASCII art format.

---

## Table of Contents

1. [Core Concepts Explained](#core-concepts)
2. [Initial Reconnaissance](#reconnaissance)
3. [Understanding JavaScript Obfuscation](#obfuscation)
4. [Deobfuscation Process](#deobfuscation)
5. [Understanding Bricks (Critical Concept)](#bricks)
6. [Encryption Layers Explained](#encryption)
7. [Dynamic Analysis & Data Extraction](#dynamic-analysis)
8. [Building the Solver](#solver)
9. [Complete Solution Walkthrough](#walkthrough)
10. [Key Takeaways](#takeaways)

---

<a name="core-concepts"></a>
## 1. Core Concepts Explained

### What is RC4?

**RC4 (Rivest Cipher 4)** is a stream cipher encryption algorithm.

**How it works in simple terms:**

1. **Key Scheduling:** Takes your password/key and uses it to shuffle a 256-number array
2. **Keystream Generation:** Produces a pseudo-random stream of bytes
3. **Encryption:** XORs (exclusive OR) your data with the keystream

**Visual example:**
```
Your data:     H  E  L  L  O  (ASCII: 72, 69, 76, 76, 79)
Keystream:    217 42 88 191 123 (generated from password)
XOR result:   157 107 28 243 196 (encrypted data)

To decrypt: XOR encrypted with same keystream → original data
```

**Why XOR is reversible:**
```
A XOR B = C
C XOR B = A  (same operation reverses it!)
```

**RC4 in this challenge:**
- Takes a 72-character hex string as the key
- Generates keystream
- XORs encrypted data byte-by-byte
- Same function decrypts (symmetric cipher)

### What is Gzip?

**Gzip** is a compression algorithm (like ZIP) that makes data smaller.

**How it works:**

1. **Find Patterns:** Looks for repeated sequences
2. **Build Dictionary:** Creates references to repeated data
3. **Replace:** Substitutes repetitions with short references

**Example:**
```
Original:  "The cat sat on the mat and the cat ran"
           └─┬─┘       └─┬─┘   └─┬─┘
Gzip sees: "the" (3x), "cat" (2x), "at" (2x)

Compressed: Uses backreferences like:
"The cat sat on <ref:the> mat and <ref:the> <ref:cat> ran"
```

**In binary:** Much more efficient, can compress 100KB → 10KB

**Why compression before encryption?**
- Smaller data = faster to encrypt
- Encrypted data has no patterns (can't compress it)
- Order matters: **Compress THEN encrypt**

### How RC4 and Gzip Work Together

**Encryption chain:**
```
Original JSON
    ↓
[Gzip compress] ────→ Binary data (smaller)
    ↓
[RC4 encrypt] ──────→ Random-looking bytes
    ↓
[Base64 encode] ────→ Text-safe string "56k2Xht..."
```

**Decryption chain (reverse order):**
```
Base64 string "56k2Xht..."
    ↓
[Base64 decode] ────→ Random bytes
    ↓
[RC4 decrypt] ──────→ Compressed binary
    ↓
[Gzip decompress] ──→ Original JSON
```

**Why this specific order?**
1. Gzip first = reduces size (JSON has lots of repetition)
2. RC4 = scrambles the compressed data (security)
3. Base64 = makes binary safe for JavaScript strings (storage)

### What is XOR?

**XOR (Exclusive OR)** is a bitwise operation fundamental to many ciphers.

**Truth table:**
```
A | B | A XOR B
--|---|--------
0 | 0 |   0
0 | 1 |   1
1 | 0 |   1
1 | 1 |   0
```

**Key property (why crypto uses it):**
```
If: C = A XOR B
Then: A = C XOR B  (reversible!)
```

**Example:**
```
Data:      01001000  (72 = 'H')
Key:       11011001  (217)
XOR:       10010001  (145 = encrypted)

Decrypt:   10010001  (145 = encrypted)
Key:       11011001  (217, same key)
XOR:       01001000  (72 = 'H', original!)
```

---

<a name="reconnaissance"></a>
## 2. Initial Reconnaissance

### Step 1: Examine Files
```bash
ls -lh
# index.html    (2KB)
# game.js       (113KB)
```

**index.html:** Simple HTML that loads Phaser.js and game.js

**game.js:** 113KB of JavaScript, appears obfuscated

### Step 2: Check if Code is Minified
```bash
head -c 200 game.js
```

**Output:** One extremely long line → minified/obfuscated

**Indicator:** No newlines, variable names like `_0x49a966`, `a0_0x9638eb`

### Step 3: Identify Obfuscation Type

**Pattern observed:**
```javascript
const a0_0x9638eb=a0_0x3fa8;(function(_0x49a966,_0x1b34ae){...
```

**Characteristics:**
- Hex-based variable names (`_0x49a966`)
- IIFE (Immediately Invoked Function Expression)
- String array with decoder function
- Typical of **obfuscator.io** or similar tools

### Step 4: Read the Writeup (Strategic)

**Writeup revealed:**
- Flag at stage 100 (actually level 99, 0-indexed)
- Encryption: Base64 → RC4 → Gzip (layered)
- Key derived from brick values
- Need to extract encrypted data at runtime

**This tells us:**
1. Static analysis alone won't work (need dynamic extraction)
2. Must find brick values in code
3. Must understand key derivation algorithm
4. Must decrypt 100 levels sequentially

---

<a name="obfuscation"></a>
## 3. Understanding JavaScript Obfuscation

### What is Obfuscation?

**Obfuscation** = Making code intentionally hard to read while keeping functionality

**Common techniques:**

1. **Variable Renaming:** `userName` → `_0x4a3b9f`
2. **String Hiding:** Strings stored in array, accessed via function
3. **Dead Code:** Useless code to confuse
4. **Control Flow Flattening:** Turns `if/else` into complex state machines
5. **Minification:** Removes whitespace/newlines

### Why Obfuscate?

**Legitimate uses:**
- Protect intellectual property
- Prevent cheating in games
- Hide API keys (bad practice, but common)

**CTF usage:**
- Make reverse engineering harder
- Force you to understand deobfuscation techniques

### IIFE Pattern

**IIFE = Immediately Invoked Function Expression**
```javascript
(function() {
    // Code here runs immediately
})();
```

**In this challenge:**
```javascript
(function(_0x49a966, _0x1b34ae) {
    // Rotates the string array to prevent static analysis
    while(true) {
        // Array manipulation logic
    }
})(a0_0x40ef, 0xf2bf5);
```

**Purpose:** 
- Runs on load to shuffle string array
- Makes static string extraction harder
- Uses magic number `0xf2bf5` as rotation key

### String Array Obfuscation

**Pattern:**
```javascript
function a0_0x40ef() {
    const _0x123 = [
        'base64string1',
        'base64string2',
        // ... 274 strings
    ];
    return _0x123;
}

function a0_0x3fa8(index) {
    const arr = a0_0x40ef();
    return customBase64Decode(arr[index]);
}
```

**How it works:**
1. Strings stored as base64 in array
2. Decoder function accesses by index
3. Custom base64 alphabet to defeat standard decoders
4. IIFE rotates array at runtime

**Example usage in code:**
```javascript
a0_0x9638eb(0x229)  // Returns decoded string at index 0x229
```

---

<a name="deobfuscation"></a>
## 4. Deobfuscation Process

### Step 1: Prettify/Format Code

**Tool:** Prettier (JavaScript formatter)
```bash
npx prettier game.js > prettier_game.js
```

**Result:**
- Adds newlines and indentation
- 113KB, 1 line → now readable with proper structure
- Variables still obfuscated but structure clear

**Before:**
```javascript
const a0_0x9638eb=a0_0x3fa8;(function(_0x49a966,_0x1b34ae){const _0x1a...
```

**After:**
```javascript
const a0_0x9638eb = a0_0x3fa8;
(function (_0x49a966, _0x1b34ae) {
  const _0x1a7707 = a0_0x9638eb;
  // ... readable structure
})();
```

### Step 2: Identify Key Functions

**Search for function definitions:**
```bash
grep -o "function a0_0x[a-z0-9]*" prettier_game.js
```

**Found:**
- `function a0_0x40ef()` - String array
- `function a0_0x3fa8()` - Decoder function

**Locate string array:**
```bash
grep -n "function a0_0x40ef" prettier_game.js
# Line 86
```

**View the array:**
```bash
sed -n '86,360p' prettier_game.js
```

**Found:** 274 base64-encoded strings

### Step 3: Discover Custom Base64

**Observation:** Standard base64 decode fails

**Standard alphabet:**
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=
```

**Custom alphabet (found in code):**
```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=
```

**Difference:** Lowercase and uppercase swapped!

**Why this matters:**
- Standard decoders fail
- Must translate to standard alphabet first
- Then decode

### Step 4: Extract and Decode Strings

**Created decoder script:**
```python
import base64

# Custom alphabet (lowercase first)
custom = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
# Standard alphabet (uppercase first)
standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

# Translation table
trans = str.maketrans(custom, standard)

strings = [
    "ZAFlBCBTBGXXC3==",  # Example from array
    # ... all 274 strings
]

for i, s in enumerate(strings):
    try:
        # Translate to standard base64
        standard_b64 = s.translate(trans)
        # Decode
        decoded = base64.b64decode(standard_b64).decode('utf-8')
        print(f"[{i}] {decoded}")
    except:
        pass
```

**Key discoveries:**
```
[19] Congratulations! You cleared all stages! Press Space to play again
[47] Game over! Press Space to restart
[95] decryptedNextLevel
[119] decryptLevel
[140] createBricks
[153] Press Space to launch
```

**Insights:**
- Game has multiple stages
- Encryption/decryption functions exist
- Bricks are created programmatically

---

<a name="bricks"></a>
## 5. Understanding Bricks (Critical Concept)

### What Are Bricks in Breakout?

**In the game:** Colored blocks you destroy with a ball

**In the code:** JavaScript objects with properties

**Brick object structure:**
```javascript
{
    x: 100,              // Position X
    y: 50,               // Position Y
    width: 60,           // Size
    height: 20,          // Size
    color: 0xff0000,     // Color (red)
    value: 0xe31329f4,   // ← THIS IS CRITICAL
    destroyed: false
}
```

### Why is `value` Important?

**The `value` property serves TWO purposes:**

1. **Game Logic:** Points earned when brick destroyed
2. **Cryptography:** Key material for RC4 encryption

**This is the clever part:** Game state is used as crypto material!

### How Bricks Become Crypto Keys

**Process:**

1. Game creates 10 initial bricks with specific `value` properties
2. These 10 values are the "seed" for the first RC4 key
3. A custom formula calculates the key from these values
4. This key decrypts level 1
5. Level 1 contains new brick values (in "specials" array)
6. Those values generate the key for level 2
7. Repeat 100 times

**Chain of keys:**
```
Initial bricks → Key1 → Decrypt Level1
Level1 specials → Key2 → Decrypt Level2
Level2 specials → Key3 → Decrypt Level3
...
Level99 specials → Key100 → Decrypt Level100 (QR code)
```

### Finding Brick Values in Code

**Search pattern:**
```bash
grep -E "0x[0-9a-f]{8}" prettier_game.js | grep "0x1f5"
```

**What this finds:**
- `0x[0-9a-f]{8}` = 32-bit hex numbers (brick values)
- `0x1f5` = Obfuscated property access for `.value`

**Results:**
```javascript
(a0_0x543e69[a0_0x9638eb(0x1f5)] = 0xe31329f4));
(a0_0x3b1ebc[a0_0x9638eb(0x1f5)] = 0x9bcfbc46));
(a0_0x4c92d6[a0_0x9638eb(0x1f5)] = 0x3ffe057));
// ... 10 total
```

**Translation:**
```javascript
brick1.value = 0xe31329f4;
brick2.value = 0x9bcfbc46;
brick3.value = 0x3ffe057;
// etc.
```

**The 10 brick values:**
```python
bricks = [
    0xe31329f4,  # Brick 1
    0x9bcfbc46,  # Brick 2
    0x3ffe057,   # Brick 3
    0x9a1b1dca,  # Brick 4
    0x66fa61da,  # Brick 5
    0xf6f2f5c5,  # Brick 6
    0x74074c6c,  # Brick 7
    0xa37be577,  # Brick 8
    0x58162ae2,  # Brick 9
    0x2113426    # Brick 10
]
```

### Why `0x1f5` Means `.value`

**Obfuscation technique:**

Instead of:
```javascript
brick.value = 0xe31329f4;
```

Code uses:
```javascript
brick[a0_0x9638eb(0x1f5)] = 0xe31329f4;
```

Where `a0_0x9638eb(0x1f5)` decodes to string `"value"`

**How to verify:**
1. Look at string array (index 0x1f5 = 501 decimal)
2. Decode that string
3. Result: `"value"`

---

<a name="encryption"></a>
## 6. Encryption Layers Explained

### The Complete Encryption Scheme

**Each level is encrypted with 3 layers:**
```
Original JSON Data
       ↓
[1. Gzip Compress] → Smaller binary
       ↓
[2. RC4 Encrypt] → Scrambled bytes (using key from bricks)
       ↓
[3. Base64 Encode] → Text string (safe for JavaScript)
```

**To decrypt (reverse order):**
```
Base64 String
       ↓
[1. Base64 Decode] → Binary bytes
       ↓
[2. RC4 Decrypt] → Compressed data (using correct key)
       ↓
[3. Gzip Decompress] → Original JSON
```

### The Key Derivation Function

**This is the formula that turns brick values into an RC4 key:**
```python
def calculate_key(brick_values):
    # Initialize accumulators with magic constants
    acc1 = 0x13572468
    acc2 = 0x24681357
    acc3 = 0xa000a
    
    # Process each brick value
    for val in brick_values:
        # Ensure 32-bit value
        val &= 0xFFFFFFFF
        
        # Accumulator 1: Simple addition
        acc1 = (acc1 + val) & 0xFFFFFFFF
        
        # Accumulator 2: Add rotated value
        # Rotate left by 7 bits
        rotated = ((val << 7) & 0xFFFFFFFF) | (val >> 25)
        acc2 = (acc2 + rotated) & 0xFFFFFFFF
        
        # Accumulator 3: XOR then add
        acc3 = (acc3 + (val ^ 0x9e3779b9)) & 0xFFFFFFFF
    
    # Concatenate as 72-character hex string
    return f"{acc1:08x}{acc2:08x}{acc3:08x}"
```

**Example with initial bricks:**
```
Input: [0xe31329f4, 0x9bcfbc46, ...]
Output: "ffecf14d6f4e884910732d33" (72 chars)
```

**Key components:**

1. **Magic constants:** `0x13572468`, `0x24681357`, `0xa000a`
   - Chosen by challenge author
   - Create initial entropy

2. **Bit rotation:** `(val << 7) | (val >> 25)`
   - Left shift 7 bits, OR with right shift 25
   - Mixes bits thoroughly

3. **XOR constant:** `0x9e3779b9`
   - Golden ratio in hex (φ × 2^32)
   - Common in hash functions

4. **Masking:** `& 0xFFFFFFFF`
   - Keeps values in 32-bit range
   - Python integers can be unlimited size

### RC4 Implementation

**The actual RC4 cipher used:**
```python
def rc4_decrypt(data, key_string):
    # Initialize state array (S-box)
    S = list(range(256))  # [0, 1, 2, ..., 255]
    j = 0
    key_bytes = key_string.encode('utf-8')
    
    # Key Scheduling Algorithm (KSA)
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        # Swap S[i] and S[j]
        S[i], S[j] = S[j], S[i]
    
    # Pseudo-Random Generation Algorithm (PRGA)
    i = j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        # Swap S[i] and S[j]
        S[i], S[j] = S[j], S[i]
        
        # Generate keystream byte
        K = S[(S[i] + S[j]) % 256]
        
        # XOR with data
        result.append(byte ^ K)
    
    return result
```

**KSA (Key Scheduling Algorithm):**
- Shuffles S-box based on key
- Creates initial permutation

**PRGA (Pseudo-Random Generation Algorithm):**
- Generates keystream bytes
- XORs with data

### JSON Level Structure

**What each decrypted level contains:**
```json
{
  "layout": [
    [1, 1, 1, 1, 1],
    [1, 0, 0, 0, 1],
    [1, 1, 1, 1, 1]
  ],
  "specials": [
    {"x": 10, "y": 20, "value": 0x12345678},
    {"x": 30, "y": 40, "value": 0xabcdef01},
    // ... 10 brick objects
  ],
  "next": "base64_encoded_next_level..."
}
```

**Fields:**

- `layout`: Grid showing brick positions (1 = brick, 0 = empty)
- `specials`: Array of 10 brick objects with `value` properties
- `next`: Encrypted data for next level (base64 string)

**Level 99 (final):**
```json
{
  "layout": [
    "XXXXXXX.XX.....XXXX.X.X...XXXXXXX",
    "X.....X.......XX.X..XXXX..X.....X",
    // ... 33 rows of ASCII art forming QR code
  ]
  // NO "specials" or "next" field
}
```

---

<a name="dynamic-analysis"></a>
## 7. Dynamic Analysis & Data Extraction

### Why Dynamic Analysis?

**Problem:** Encrypted data is generated at runtime, not visible in static code

**Solution:** Use browser debugger to extract data when game initializes

### Setting Up Firefox Debugger

**Steps:**

1. Open `index.html` in Firefox
2. Press `F12` → Developer Tools
3. Click **Debugger** tab
4. Find `game.js` in left panel
5. Use `Ctrl+F` to search for `new Phaser`

**What to look for:**
```javascript
new Phaser.Game({
    // Game configuration
    // This is where encrypted data is accessed
});
```

### Setting the Breakpoint

**Goal:** Pause execution when game initializes, before it tries to decrypt

**Method:**

1. Search for: `new Phaser`
2. Click line number to set breakpoint (blue marker)
3. Refresh page (`F5`)
4. Execution pauses at breakpoint

**What you see:**
- Code is paused
- Variables in scope are accessible
- Console is active

### Extracting Encrypted Data

**In the Console tab (while paused):**
```javascript
// The decoder function is a0_0x3fa8
// Index 0x1fc (508 decimal) contains encrypted data
const encrypted = a0_0x3fa8(0x1fc);

console.log(encrypted);
// Outputs the long base64 string
```

**Copy the output:**
- Right-click → Copy
- Save to `encrypted_data.txt`

**Why this works:**
- Debugger has access to all variables in scope
- The decoder function `a0_0x3fa8` is accessible
- Index `0x1fc` was found by searching code for where encrypted data is stored

### Finding the Encrypted Data Index

**How we knew to use `0x1fc`:**
```bash
grep -n "0x1fc" prettier_game.js
```

**Found:**
```javascript
a0_0x9638eb(0x229) = a0_0x9638eb(0x1fc)
```

Where `0x229` decodes to something like `"encryptedLevelData"`

### Alternative: Automated Extraction

**Could also use Playwright/Puppeteer:**
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page()
    page.goto('file:///path/to/index.html')
    
    # Wait for game to load
    page.wait_for_function('typeof a0_0x3fa8 !== "undefined"')
    
    # Extract encrypted data
    encrypted = page.evaluate('a0_0x3fa8(0x1fc)')
    
    with open('encrypted_data.txt', 'w') as f:
        f.write(encrypted)
```

---

<a name="solver"></a>
## 8. Building the Solver

### Solver Architecture

**Flow:**
```
1. Read encrypted_data.txt
2. Calculate initial key from 10 brick values
3. For level 0 to 99:
   a. Base64 decode
   b. RC4 decrypt
   c. Gzip decompress
   d. Parse JSON
   e. If level 99: extract QR code, done
   f. Otherwise: get "specials" → calculate new key
   g. Get "next" → set as new encrypted data
4. Convert ASCII art to QR code image
5. Scan for flag
```

### Complete Solver Code
```python
#!/usr/bin/env python3
import base64
import gzip
import json
from PIL import Image
import numpy as np

# Initial brick values (extracted from prettier_game.js)
bricks = [
    0xe31329f4, 0x9bcfbc46, 0x3ffe057, 0x9a1b1dca, 0x66fa61da,
    0xf6f2f5c5, 0x74074c6c, 0xa37be577, 0x58162ae2, 0x2113426
]

def calculate_key(brick_values):
    """
    Custom key derivation function
    Takes array of 10 brick values, returns 72-char hex string
    """
    acc1 = 0x13572468
    acc2 = 0x24681357
    acc3 = 0xa000a
    
    for val in brick_values:
        # Ensure 32-bit
        val &= 0xFFFFFFFF
        
        # Accumulator 1: addition
        acc1 = (acc1 + val) & 0xFFFFFFFF
        
        # Accumulator 2: rotate then add
        rotated = ((val << 7) & 0xFFFFFFFF) | (val >> 25)
        acc2 = (acc2 + rotated) & 0xFFFFFFFF
        
        # Accumulator 3: XOR with golden ratio, then add
        acc3 = (acc3 + (val ^ 0x9e3779b9)) & 0xFFFFFFFF
    
    # Return as concatenated hex string
    return f"{acc1:08x}{acc2:08x}{acc3:08x}"

def rc4_decrypt(data, key_string):
    """
    RC4 stream cipher
    Same function encrypts and decrypts (symmetric)
    """
    # Initialize S-box
    S = list(range(256))
    j = 0
    key_bytes = key_string.encode('utf-8')
    
    # Key Scheduling Algorithm
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
    
    # Pseudo-Random Generation Algorithm
    i = j = 0
    result = bytearray()
    
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]  # Swap
        
        # Generate keystream byte and XOR
        keystream_byte = S[(S[i] + S[j]) % 256]
        result.append(byte ^ keystream_byte)
    
    return result

# Read encrypted data
with open('encrypted_data.txt', 'r') as f:
    encrypted_data = f.read().strip()

# Calculate initial key
key = calculate_key(bricks)
print(f"Initial key: {key}\n")

# Decrypt 100 levels
data = encrypted_data
for level in range(100):
    print(f"Decrypting level {level + 1}/100", end='\r')
    
    # Layer 1: Base64 decode
    data = base64.b64decode(data)
    
    # Layer 2: RC4 decrypt
    data = rc4_decrypt(data, key)
    
    # Layer 3: Gzip decompress
    data = gzip.decompress(data)
    
    # Parse JSON
    level_data = json.loads(data.decode('utf-8'))
    
    # Check if final level
    if level == 99 or 'layout' in level_data:
        print("\n\nReached final level!")
        
        # Extract ASCII art QR code
        layout = level_data['layout']
        
        # Convert to image
        # 'X' = black pixel (0)
        # '.' = white pixel (255)
        img_array = []
        for row in layout:
            img_row = [0 if char == 'X' else 255 for char in row]
            img_array.append(img_row)
        
        img_array = np.array(img_array, dtype=np.uint8)
        
        # Scale up 10x for easier scanning
        img_array = np.repeat(np.repeat(img_array, 10, axis=0), 10, axis=1)
        
        # Save as PNG
        img = Image.fromarray(img_array)
        img.save('qr.png')
        
        print("QR code saved: qr.png")
        print("Scan with phone camera for flag!")
        break
    
    # Extract next level's key from "specials"
    if 'specials' in level_data and level_data['specials']:
        special_values = [brick['value'] for brick in level_data['specials']]
        key = calculate_key(special_values)
    
    # Get next encrypted level
    if 'next' in level_data:
        data = level_data['next']
    else:
        print(f"\nError: Level {level} has no 'next' field")
        break
```

### Code Explanation - Line by Line

**Key Calculation:**
```python
acc1 = (acc1 + val) & 0xFFFFFFFF
```
- `acc1 + val`: Add brick value to accumulator
- `& 0xFFFFFFFF`: Mask to 32 bits (prevents overflow)

**Bit Rotation:**
```python
rotated = ((val << 7) & 0xFFFFFFFF) | (val >> 25)
```
- `val << 7`: Shift left 7 bits (bits fall off left side)
- `val >> 25`: Shift right 25 bits (brings back the 7 lost bits)
- `|`: OR combines them (circular rotation)

**RC4 Swapping:**
```python
S[i], S[j] = S[j], S[i]
```
- Python tuple unpacking for swap
- Equivalent to: `temp = S[i]; S[i] = S[j]; S[j] = temp`

**XOR Encryption:**
```python
result.append(byte ^ keystream_byte)
```
- `^` is XOR operator
- Each data byte XORed with keystream byte
- Produces encrypted byte

**Image Scaling:**
```python
img_array = np.repeat(np.repeat(img_array, 10, axis=0), 10, axis=1)
```
- `axis=0`: Repeat rows 10 times (vertical scaling)
- `axis=1`: Repeat columns 10 times (horizontal scaling)
- 33×33 QR code → 330×330 pixels (easier to scan)

---

<a name="walkthrough"></a>
## 9. Complete Solution Walkthrough

### Phase 1: Setup
```bash
# Create working directory
mkdir -p ~/seccon14CTF-2025/breaking_out
cd ~/seccon14CTF-2025/breaking_out

# Extract challenge files
unzip breaking_out.zip
```

### Phase 2: Static Analysis

**Step 1: Prettify code**
```bash
npx prettier game.js > prettier_game.js
```

**Step 2: Find string array**
```bash
grep -n "function a0_0x40ef" prettier_game.js
# Line 86
```

**Step 3: Extract strings**
```bash
sed -n '86,360p' prettier_game.js > strings.txt
```

**Step 4: Find brick values**
```bash
grep -E "0x[0-9a-f]{8}" prettier_game.js | grep "0x1f5"
```

**Results:**
```
0xe31329f4
0x9bcfbc46
0x3ffe057
0x9a1b1dca
0x66fa61da
0xf6f2f5c5
0x74074c6c
0xa37be577
0x58162ae2
0x2113426
```

### Phase 3: Dynamic Analysis

**Step 1: Open in Firefox**
```bash
firefox index.html
```

**Step 2: Set breakpoint**
- `F12` → Debugger
- Search `new Phaser`
- Click line number

**Step 3: Extract data**
```javascript
// In Console (while paused)
a0_0x3fa8(0x1fc)
```

**Step 4: Save to file**
```bash
cat > encrypted_data.txt
# Paste the long base64 string
# Ctrl+D to save
```

### Phase 4: Build Solver

**Create solve.py with the code from section 8**

### Phase 5: Run Solver
```bash
python3 solve.py
```

**Output:**
```
Initial key: ffecf14d6f4e884910732d33

Decrypting level 1/100
Decrypting level 2/100
...
Decrypting level 99/100

Reached final level!
QR code saved: qr.png
Scan with phone camera for flag!
```

### Phase 6: Extract Flag

**Method 1: Phone camera**
- Open camera app
- Point at `qr.png` on screen
- Flag appears

**Method 2: QR code reader tool**
```bash
zbarimg qr.png
```

**Flag:**
```
SECCON{H4ve_y0u_3ver_p14yed_Atari?_SQiOIVX6HPtRekE1vTn4}
```

---

<a name="takeaways"></a>
## 10. Key Takeaways & Future Reference

### Core Skills Learned

**1. JavaScript Deobfuscation**
- Recognize obfuscation patterns (IIFE, hex names, string arrays)
- Use prettifiers to format code
- Extract and decode string arrays
- Identify custom encoding schemes

**2. Dynamic Analysis**
- Use browser debugger effectively
- Set breakpoints at initialization
- Extract runtime data from scope
- Intercept function calls

**3. Cryptography**
- Understand layered encryption (Base64 → RC4 → Gzip)
- Implement symmetric ciphers
- Recognize key derivation functions
- Know when order matters (compress before encrypt)

**4. Reverse Engineering Methodology**
- Read writeups for high-level understanding
- Static analysis for code structure
- Dynamic analysis for runtime data
- Combine both approaches

### Common CTF Patterns

**Pattern 1: Game State as Crypto Material**
- Game variables used as keys/passwords
- Must play game or extract state
- Common in web/reversing challenges

**Pattern 2: Nested Encryption**
- Multiple layers (Base64 → Cipher → Compression)
- Each layer needs different key
- Must decrypt sequentially

**Pattern 3: Custom Encodings**
- Modified Base64 alphabets
- Custom character sets
- Requires translation before standard decode

**Pattern 4: Obfuscation for Protection**
- String hiding in arrays
- IIFE for runtime manipulation
- Hex variable names
- Dead code injection

### How to Identify These in Future

**Crypto Indicators:**
```bash
# Search for crypto keywords
grep -i "encrypt\|decrypt\|cipher\|rc4\|aes" code.js

# Look for base64
grep -i "base64\|atob\|btoa" code.js

# Find compression
grep -i "gzip\|deflate\|inflate" code.js
```

**Key Derivation Indicators:**
```bash
# Bitwise operations (often in crypto)
grep -E "<<|>>|\^|&" code.js

# XOR with constants
grep "0x[0-9a-f]" code.js
```

**Obfuscation Indicators:**
- One-line code (minified)
- Hex variable names (`_0x4a3b`)
- IIFE patterns
- String arrays with decoder functions

### Debugging Tips

**When solver fails:**

1. **Check each layer individually**
```python
# Test base64
decoded = base64.b64decode(data)
print(decoded[:100])  # Should be binary

# Test RC4
decrypted = rc4_decrypt(decoded, key)
print(decrypted[:100])  # Should look compressed

# Test gzip
decompressed = gzip.decompress(decrypted)
print(decompressed[:100])  # Should be JSON
```

2. **Verify key calculation**
```python
# Print intermediate values
for val in bricks:
    print(f"Processing: 0x{val:08x}")
print(f"Final key: {key}")
```

3. **Check JSON structure**
```python
import json
data = json.loads(decompressed)
print(data.keys())  # Should show: layout, specials, next
```

### Questions & Confusions Addressed

**Q: What are bricks?**
A: JavaScript objects representing game elements. Their `.value` property is used as crypto key material.

**Q: How does RC4 work?**
A: Stream cipher that generates keystream from password, XORs with data. Same operation encrypts/decrypts.

**Q: How does Gzip work?**
A: Finds repeated patterns, replaces with references. Like shorthand for repetitive data.

**Q: Why both RC4 and Gzip?**
A: Gzip compresses (smaller), RC4 encrypts (security). Order matters: compress then encrypt.

**Q: How to know what encryption without writeup?**
A: Search code for crypto keywords, test layers individually, recognize patterns from experience.

**Q: Why level 99 not 100?**
A: Python counts from 0. `range(100)` = 0-99 = 100 iterations total.

**Q: How to find brick values?**
A: Search for 32-bit hex initialization (`0x[0-9a-f]{8}`), look for repeated patterns accessing `.value`.

**Q: What is XOR?**
A: Bitwise operation where same input twice = original. Used in RC4 because it's reversible.

### Tools Reference

**Essential tools:**
- Firefox Developer Tools (debugger)
- Prettier (code formatter)
- Python (solver scripting)
- grep/sed (text processing)
- PIL/numpy (image generation)

**Useful libraries:**
```python
import base64      # Base64 encoding/decoding
import gzip        # Gzip compression/decompression
import json        # JSON parsing
from PIL import Image  # Image creation
import numpy as np     # Array operations
```

### Resources for Learning

**Cryptography:**
- CryptoHack (cryptohack.org) - Interactive crypto challenges
- Applied Cryptography by Bruce Schneier

**Reverse Engineering:**
- Crackmes.one - Practice binaries
- OWASP WebGoat - Web security

**JavaScript Obfuscation:**
- Obfuscator.io - See how it works
- JS-Beautify - Practice deobfuscating

**CTF Practice:**
- PicoCTF - Beginner-friendly
- OverTheWire - Progressive difficulty
- CTFtime.org - Find ongoing CTFs

---

## Conclusion

This challenge demonstrated:
1. Multi-layer encryption (Base64 → RC4 → Gzip)
2. Custom key derivation from game state
3. JavaScript obfuscation techniques
4. Dynamic analysis with browser debugger
5. Image generation from data

**Key insight:** Game mechanics and crypto were intertwined. Brick values served dual purpose - game scoring and encryption keys. This creative design required understanding both the game logic and cryptographic implementation.

**Skills gained:**
- Reading obfuscated JavaScript
- Extracting runtime data
- Implementing cipher algorithms
- Chaining decryption operations
- Converting data to visual formats

Keep this writeup for future reference when encountering:
- Nested encryption challenges
- JavaScript obfuscation
- Game-based CTFs
- Custom crypto implementations
- Multi-step reverse engineering tasks
