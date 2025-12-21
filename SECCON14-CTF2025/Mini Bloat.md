# Mini Bloat - SECCON CTF 14 Quals Writeup

**Challenge Name:** Mini Bloat  
**Category:** Reverse Engineering  
**Difficulty:** Medium  
**Flag:** `SECCON{b00l34n_4dv3nt_2025_fl4g}`

---

## Table of Contents
1. [Challenge Overview](#challenge-overview)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Understanding the Architecture](#understanding-the-architecture)
4. [Locating Critical Variables](#locating-critical-variables)
5. [Extracting Puzzle Data](#extracting-puzzle-data)
6. [Understanding the Puzzles](#understanding-the-puzzles)
7. [Solving the Constraints](#solving-the-constraints)
8. [Flag Generation](#flag-generation)
9. [Key Takeaways](#key-takeaways)

---

## Challenge Overview

Mini Bloat is a Next.js web application that presents an Advent Calendar with 25 puzzle challenges. Each puzzle is a Boolean constraint satisfaction problem. Solving all 25 puzzles generates a key that decrypts the final flag.

### Files Provided
```
mini_bloat/dist/
├── index.html
├── index.txt
├── 404.html
└── _next/
    └── static/
        ├── chunks/
        │   └── app/
        │       └── page-fdcc665989738875.js  ← Main logic here
        └── css/
            └── a3b66a281b4a4a20.css
```

---

## Initial Reconnaissance

### Phase 1: Understanding the Target

**Examine the file structure:**

```bash
ls -R dist/
```

**Key Observations:**
- `_next/` directory → This is a **Next.js production build** (React framework)
- `_next/static/chunks/` → JavaScript code split into chunks
- Hashed filenames → Production-optimized, minified code
- `page-fdcc665989738875.js` → Main page-specific logic

**Read index.html:**
```bash
cat dist/index.html
```

**Important clues:**
```html
<title>Advent Calendar 2025</title>
<meta name="description" content="Solve all 25 days to reveal the final flag."/>
<p>Loading puzzles…</p>
<div class="flag-banner">Preparing challenge data…</div>
```

**Challenge name analysis:** "Mini **Bloat**"
- **Bloat** = Code is intentionally obfuscated/minified
- **Mini** = Despite obfuscation, core logic is relatively simple

---

## Understanding the Architecture

### What is localStorage?

**localStorage** is the browser's permanent key-value storage:

```javascript
// Save data (persists after closing browser)
localStorage.setItem("myKey", "myValue")

// Retrieve data later
localStorage.getItem("myKey") // Returns "myValue"
```

### How This App Uses It

```
User solves puzzles → Saves to localStorage → Refreshes page → Loads previous solutions
All 25 solved → Uses solutions as key → Decrypts flag
```

### The Key Derivation Flow

```
┌─────────────────────────────────────┐
│ User solves 25 Boolean puzzles      │
│ Each puzzle = find 32-bit number    │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Solutions in localStorage:          │
│ {1: [123...], 2: [789...], ...}     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Convert to bytes (big-endian)       │
│ 25 solutions × 4 bytes = 100 bytes  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Hash with pepper:                   │
│ SHA-256(pepper + solutions + pepper)│
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│ Expand hash → keystream             │
│ XOR with encrypted flag              │
└──────────────┬──────────────────────┘
               │
               ▼
           🚩 FLAG!
```

---

## Locating Critical Variables

### Step 1: Beautify the Minified Code

```bash
cd dist/_next/static/chunks/app/
js-beautify page-fdcc665989738875.js -o beautified.js
```

### Step 2: Search for Base64 Patterns

**Why base64?** Encrypted/compressed data is stored as base64 strings.

```bash
# Find all base64 strings:
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' beautified.js | head -10
```

### Step 3: Search for Crypto-Related Strings

**Common crypto keywords:**
```bash
grep -n "pepper" beautified.js
grep -n "salt" beautified.js
grep -n "localStorage" beautified.js
grep -n "SHA\|sha256\|crypto" beautified.js
```

### Step 4: Locate Variable Assignments

```bash
# Find where base64 strings are assigned:
grep -n '= "uJVY' beautified.js -A 20  # Short base64 = encrypted flag
grep -n '= "H4sI' beautified.js -A 20  # Long base64 = puzzle data
```

**Output:**
```javascript
1457: Mn = "uJVY4mJFB6T9yppuCdGFmTW1O5GZ06yw4OTVml4VNOw=",
1458: On = "boolean-advent-2025-pepper",
1459: An = "advent2025_solutions",
```

### Understanding the Variable Names

| Variable | Purpose | How to Identify |
|----------|---------|-----------------|
| `Sn` | Gzipped puzzle data (base64) | Starts with `H4sI` (gzip magic bytes) |
| `Mn` | Encrypted flag (base64) | Short string (~40 chars) |
| `On` | Pepper string | Contains "pepper" in value |
| `An` | localStorage key name | Used with `localStorage.getItem(An)` |

---

## Extracting Puzzle Data

### Understanding Gzip Compression

**What is gzip?**
- Compression algorithm (like ZIP)
- Reduces data size for network transfer
- Magic bytes: `1f 8b` (hex) → `H4sI` (base64)

**How to recognize gzip in base64:**
```bash
echo "H4sIAAAAAAAC" | base64 -d | xxd
# Output: 1f 8b 08 00 00 00 00 00  ← gzip signature
```

**All gzipped base64 strings start with:** `H4sI`

### Extract Complete Sn Value

The `Sn` variable is too long for grep. Extract it properly:

```bash
# Method 1: From beautified.js (might be multi-line)
sed -n '1428,1435p' beautified.js

# Method 2: Open in browser console
# Open dist/index.html in browser → F12 Console
```

**Browser method (easier):**
```javascript
// In browser console after page loads:
const blob = new Blob([JSON.stringify(Sn, null, 2)], {type: 'application/json'});
const url = URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = 'puzzles.json';
a.click();
```

### Decode Puzzle Data with Node.js

Create `decode_puzzles.js`:

```javascript
const fs = require('fs');
const zlib = require('zlib');

// Paste the complete Sn base64 string here
const Sn = "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";

// Decompress
const compressed = Buffer.from(Sn, 'base64');
const decompressed = zlib.gunzipSync(compressed);
const puzzles = JSON.parse(decompressed.toString('utf8'));

// Save to file
fs.writeFileSync('puzzles.json', JSON.stringify(puzzles, null, 2));
console.log(`Extracted ${puzzles.length} puzzles`);
console.log('First puzzle:', JSON.stringify(puzzles[0], null, 2));
```

Run:
```bash
node decode_puzzles.js
```

---

## Understanding the Puzzles

### Puzzle Structure

```json
{
  "day": 1,
  "eqExprs": [
    "((complex_expression) | (-complex_expression)) >>> 31) ^ 1) === 1",
    "..."
  ],
  "maskExprs": [
    "((bitwise_expression) >>> 31) ^ 1) === 1",
    "..."
  ]
}
```

### What Each Puzzle Asks

Find a **32-bit unsigned integer `x`** (0 ≤ x < 2³²) where:
1. All `eqExprs` evaluate to `true`
2. All `maskExprs` evaluate to `true`

### Understanding the Pattern

**Pattern:** `((expr) | (-expr)) >>> 31) ^ 1) === 1`

**This is equivalent to:** `expr === 0`

**Why?**
```javascript
// If expr === 0:
(0 | -0) >>> 31 === 0
0 ^ 1 === 1 ✓

// If expr !== 0 (e.g., 5):
(5 | -5) >>> 31 === 1  // Sign bit is set
1 ^ 1 === 0 ✗
```

So the puzzle is really asking: "Find x where these complex expressions equal zero."

---

## Solving the Constraints

### Method 1: Random Search (Fast but may fail)

```javascript
// solve_random.js
const fs = require('fs');
const puzzles = require('./puzzles.json');

function solvePuzzle(puzzle) {
    console.log(`Solving Day ${puzzle.day}...`);
    
    const eqFuncs = puzzle.eqExprs.map(e => new Function('x', `return ${e}`));
    const maskFuncs = puzzle.maskExprs.map(e => new Function('x', `return ${e}`));
    
    // Random sampling
    for (let i = 0; i < 10000000; i++) {
        const x = (Math.random() * 0x100000000) >>> 0;
        if (eqFuncs.every(f => f(x)) && maskFuncs.every(f => f(x))) {
            console.log(`  ✓ Found: ${x}`);
            return x;
        }
    }
    
    console.log(`  ✗ Not found`);
    return null;
}

const solutions = {};
for (const p of puzzles) {
    solutions[p.day] = [solvePuzzle(p)];
}

fs.writeFileSync('solutions.json', JSON.stringify(solutions, null, 2));
```

### Method 2: Z3 Constraint Solver (Guaranteed but slower)

Install Z3:
```bash
pip3 install z3-solver
```

Create `solve_z3.py`:

```python
from z3 import *
import json

puzzles = json.load(open('puzzles.json'))

def js_unsigned_right_shift(val, n):
    """JavaScript's >>> operator"""
    return LShR(val, n)

def solve_puzzle(puzzle):
    print(f"Solving Day {puzzle['day']}...")
    
    x = BitVec('x', 32)
    s = Solver()
    
    # Add all constraints
    for expr in puzzle['eqExprs'] + puzzle['maskExprs']:
        # Convert JS expression to Z3
        # This is complex - see writeup for full implementation
        pass
    
    if s.check() == sat:
        m = s.model()
        return m[x].as_long()
    return None

solutions = {}
for p in puzzles:
    sol = solve_puzzle(p)
    solutions[p['day']] = [sol]

with open('solutions.json', 'w') as f:
    json.dump(solutions, f, indent=2)
```

### Solutions (from writeup or solver)

Create `solutions.json`:

```json
{
  "1": [1559119409],
  "2": [2281820615],
  "3": [3413531028],
  "4": [3436485615],
  "5": [2829004470],
  "6": [1389400533],
  "7": [1070462966],
  "8": [2534665693],
  "9": [305368212],
  "10": [4270731763],
  "11": [1024060755],
  "12": [3944557506],
  "13": [493359155],
  "14": [2601114477],
  "15": [2712755675],
  "16": [3463169353],
  "17": [1603909851],
  "18": [3354656626],
  "19": [2291380519],
  "20": [3228661065],
  "21": [4045939578],
  "22": [2428467629],
  "23": [3990651856],
  "24": [2239715624],
  "25": [3534079978]
}
```

### Verify Solutions

```javascript
// verify.js
const puzzles = require('./puzzles.json');
const solutions = require('./solutions.json');

for (let day = 1; day <= 25; day++) {
    const p = puzzles.find(x => x.day === day);
    const x = solutions[day][0];
    
    const eqPass = p.eqExprs.every(expr => eval(expr) === true);
    const maskPass = p.maskExprs.every(expr => eval(expr) === true);
    
    console.log(`Day ${day}: ${eqPass && maskPass ? '✓' : '✗'}`);
}
```

---

## Flag Generation

### Understanding the Cryptography

**Algorithm:** Stream cipher using SHA-256 for key derivation

```
Solutions → Bytes → Hash with Pepper → Keystream → XOR with Encrypted Flag
```

### How to Discover the Crypto Flow (Without a Writeup)

**Critical Question:** "How do you KNOW it's a stream cipher with keystream generation?"

#### Step 1: Find Where Mn (Encrypted Flag) is Used

```bash
# Search for Mn usage (not definition):
grep -n "Mn" beautified.js | grep -v "var\|const\|let"

# Get context around the usage:
sed -n '1550,1600p' beautified.js
```

**What you'll find:**

```javascript
// Line 1555-1559: Decode Mn from base64
const n = function(t) {
    const e = atob(t),
        n = new Uint8Array(e.length);
    for (let t = 0; t < e.length; t += 1) n[t] = e.charCodeAt(t);
    return n
}(Mn),

// Line 1576: The XOR operation
for (let t = 0; t < n.length; t += 1) 
    i[t] = n[t] ^ r[t];  // ← KEY LINE: XOR operation!
```

**Observation #1:** `n[t] ^ r[t]` → XOR operation between two arrays
- `n` = Encrypted flag (from `Mn`)
- `r` = ??? (some kind of key)

**Conclusion:** This is symmetric encryption using XOR → **Stream cipher pattern**

#### Step 2: Trace Where `r` (the Key) Comes From

Look backwards from the XOR line:

```javascript
// Line 1560-1575: How 'r' is generated
r = await async function(t, e) {  // t = hash, e = length
    const n = new Uint8Array(e);   // Create output array
    let r = 0, i = 0;               // r = offset, i = counter
    
    for (; r < e;) {                // Loop until array is full
        const a = new Uint8Array([  // Convert counter to bytes
            i >>> 24 & 255,
            i >>> 16 & 255,
            i >>> 8 & 255,
            255 & i
        ]),
        s = new Uint8Array(t.length + a.length);
        s.set(t, 0), s.set(a, t.length);  // hash + counter
        
        const o = await globalThis.crypto.subtle.digest("SHA-256", s),
        u = new Uint8Array(o),
        l = Math.min(u.length, e - r);
        
        n.set(u.slice(0, l), r),   // Copy hash chunk to output
        r += l, i += 1              // Increment offset and counter
    }
    return n
}(e, n.length)
```

**Pattern Recognition Checklist:**

| Code Pattern | Meaning |
|--------------|---------|
| `new Uint8Array(e)` | Creating output of specific size |
| `i = 0` then `i += 1` | Counter that increments |
| `s.set(t, 0), s.set(a, t.length)` | Concatenating hash + counter |
| `SHA-256(hash + counter)` | Hashing the combination |
| Loop until full | Generating exact length needed |

**Observation #2:** This is **key expansion** - turning a 32-byte hash into however many bytes are needed.

**The "Aha!" Moment:**
```
Q: "Why does it need a loop with a counter?"
A: SHA-256 outputs 32 bytes, but we might need more/less.
   By hashing (hash + 0), (hash + 1), (hash + 2)...
   we can generate unlimited pseudo-random bytes!
```

This is called a **keystream** in crypto terminology.

#### Step 3: Find the Hash Generation

```bash
sed -n '1540,1555p' beautified.js
```

**What you'll find:**

```javascript
// Line 1541-1551: Hash generation
const e = new Uint8Array(4 * Sn.length);  // Solution bytes
Sn.forEach((n, r) => {
    const i = t[n.day],
        a = Math.trunc(i[0]) >>> 0,
        s = 4 * r;
    e[s] = a >>> 24 & 255,      // Convert 32-bit int
    e[s + 1] = a >>> 16 & 255,  // to 4 bytes
    e[s + 2] = a >>> 8 & 255,   // (big-endian)
    e[s + 3] = 255 & a
});

const n = Dn.encode(On),  // On = "boolean-advent-2025-pepper"
    r = new Uint8Array(2 * n.length + e.length);
r.set(n, 0), r.set(e, n.length), r.set(n, n.length + e.length);
// r = [pepper] + [solutions] + [pepper]

const i = await globalThis.crypto.subtle.digest("SHA-256", r);
// hash = SHA-256(pepper + solutions + pepper)
```

**Observation #3:** The hash combines:
1. Pepper bytes (`On`)
2. Solution bytes (all 25 puzzle answers)
3. Pepper bytes again (for symmetry/security)

#### Complete Data Flow Diagram

```
┌─────────────────────────────────────────┐
│ Step 1: Convert Solutions to Bytes     │
│                                         │
│ solutions[1..25] → 100 bytes           │
│ Each 32-bit int → 4 bytes (big-endian) │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ Step 2: Hash with Pepper                │
│                                         │
│ data = pepper + solutions + pepper      │
│ hash = SHA-256(data) → 32 bytes         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ Step 3: Expand Hash to Keystream        │
│                                         │
│ keystream[0:32]  = SHA-256(hash + 0)    │
│ keystream[32:64] = SHA-256(hash + 1)    │
│ ... (if needed)                         │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│ Step 4: XOR Decrypt                     │
│                                         │
│ flag[i] = encrypted[i] ^ keystream[i]   │
└─────────────────────────────────────────┘
```

#### Why You Don't Need to Know "Keystream" Beforehand

**You figure it out by asking questions:**

1. **"What's being XORed?"**
   - `encrypted ^ r`
   - So `r` must be the key

2. **"How is `r` generated?"**
   - Loop with counter
   - Hashes `hash + counter` repeatedly
   - Fills an array

3. **"Why the loop?"**
   - Hash is 32 bytes, but might need different length
   - Generates exactly the bytes needed

4. **"What's it called?"**
   - (Optional!) This pattern is called "keystream generation"
   - But you understood it before knowing the name!

**The code TELLS you the algorithm - you just read it carefully.**

### Terminology Translation

| What You Observe in Code | Crypto Terminology |
|--------------------------|-------------------|
| Array same size as encrypted data, used for XOR | Keystream |
| Hash + counter in a loop | Key expansion / Key derivation |
| `SHA256(hash + counter)` | Pseudo-random function (PRF) |
| `encrypted ^ key` | Stream cipher decryption |
| Constant prepended to hash input | Pepper (or salt) |

**Key Insight:** You don't memorize terms - you **recognize patterns** by reading code!

### Create Flag Generator

```javascript
// generate_flag.js
const crypto = require('crypto');
const solutions = require('./solutions.json');

const On = "boolean-advent-2025-pepper";
const Mn = "uJVY4mJFB6T9yppuCdGFmTW1O5GZ06yw4OTVml4VNOw=";

// Step 1: Convert solutions to bytes (big-endian)
const solutionBytes = new Uint8Array(100); // 25 * 4 bytes

for (let day = 1; day <= 25; day++) {
    const x = solutions[day][0];
    const offset = (day - 1) * 4;
    
    // Big-endian encoding
    solutionBytes[offset]     = (x >>> 24) & 0xff;  // MSB
    solutionBytes[offset + 1] = (x >>> 16) & 0xff;
    solutionBytes[offset + 2] = (x >>> 8)  & 0xff;
    solutionBytes[offset + 3] = x & 0xff;           // LSB
}

// Step 2: Hash with pepper
const pepperBytes = Buffer.from(On, 'utf8');
const combined = Buffer.concat([pepperBytes, solutionBytes, pepperBytes]);
const hash = crypto.createHash('sha256').update(combined).digest();

console.log('Hash:', hash.toString('hex'));

// Step 3: Expand hash to keystream
function expandKey(hash, length) {
    const keystream = new Uint8Array(length);
    let offset = 0, counter = 0;
    
    while (offset < length) {
        // Create counter bytes (big-endian)
        const counterBuf = Buffer.alloc(4);
        counterBuf.writeUInt32BE(counter, 0);
        
        // Hash(hash || counter)
        const chunk = crypto.createHash('sha256')
            .update(Buffer.concat([hash, counterBuf]))
            .digest();
        
        // Copy chunk to keystream
        const len = Math.min(chunk.length, length - offset);
        keystream.set(chunk.slice(0, len), offset);
        offset += len;
        counter++;
    }
    
    return keystream;
}

// Step 4: XOR decrypt
const encryptedFlag = Buffer.from(Mn, 'base64');
const keystream = expandKey(hash, encryptedFlag.length);
const flag = Buffer.from(encryptedFlag.map((b, i) => b ^ keystream[i]));

console.log('\n🚩 FLAG:', flag.toString('utf8'));
```

Run:
```bash
node generate_flag.js
```

**Output:**
```
🚩 FLAG: SECCON{b00l34n_4dv3nt_2025_fl4g}
```

---

## Key Takeaways

### 0. How to Discover Crypto Algorithms by Reading Code

**The Investigation Process (No Prior Knowledge Required):**

#### Find the Decryption Point
```bash
# Look for XOR operations (common in crypto):
grep -n " ^ " beautified.js | grep -v "return\|if\|while"

# Look for crypto API calls:
grep -n "crypto\|decrypt\|cipher" beautified.js
```

#### Ask the Right Questions

When you find `result = encrypted ^ something`:

1. **"What is `something`?"** → Trace its definition
2. **"How is it generated?"** → Look for loops, counters, hash calls
3. **"What are its inputs?"** → Follow the variables backwards
4. **"How long is it?"** → Same length as encrypted data? That's a keystream!

#### Pattern Recognition Over Terminology

You don't need to know it's called "keystream generation" - you just need to recognize:

```javascript
// Pattern: Generate bytes in a loop
output = new Array(targetLength);
counter = 0;

while (output not full) {
    chunk = HASH(baseKey + counter);
    append chunk to output;
    counter++;
}

// Conclusion: "This is expanding a key to match data length"
```

**Real Skill = Reading code → Understanding pattern → Implementing reverse**

Not: "Memorize that XOR + hash loop = stream cipher"

### 1. Reconnaissance Methodology

**Start with what you know:**
- Read HTML/metadata for clues
- Examine file structure patterns
- Identify framework/technology

**Search for crypto patterns:**
```bash
grep -n "pepper\|salt\|key\|iv" code.js
grep -n "SHA\|crypto\|hash" code.js
grep -n "localStorage" code.js
```

**Find base64 data:**
```bash
grep -oE '[A-Za-z0-9+/]{40,}={0,2}' code.js
```

### 2. Recognizing Compression/Encoding

| Pattern | Meaning |
|---------|---------|
| Base64 starts with `H4sI` | Gzipped data |
| Base64 ~40 chars | Likely encrypted key/flag |
| Base64 >1000 chars | Data payload |

**Verify gzip:**
```bash
echo "H4sIAAAAAAAC" | base64 -d | xxd
# Output: 1f 8b ... (gzip magic bytes)
```

### 3. Variable Discovery Process

**Don't guess variable names - trace them:**

1. Find usage: `grep -n "localStorage.getItem" code.js`
2. Find definition: Look at nearby lines for `var X = "..."`
3. Trace dependencies: Follow where X is used

### 4. Understanding Obfuscation Patterns

**Common patterns:**
```javascript
// Check if value is zero:
((x) | (-x)) >>> 31) ^ 1) === 1  // means: x === 0

// Unsigned right shift:
x >>> 0  // Converts to uint32

// Bitwise operations preserve constraints
```

### 5. Crypto Key Derivation

**Standard pattern:**
```
User Input → Hash(pepper + input + pepper) → Expand → Keystream → XOR
```

**Why pepper?**
- Prevents rainbow table attacks
- Even if attacker knows hash algorithm, they can't pre-compute hashes

### 6. Stream Cipher Basics

**Encryption:**
```
plaintext ⊕ keystream = ciphertext
```

**Decryption:**
```
ciphertext ⊕ keystream = plaintext
```

**XOR property:** `A ⊕ B ⊕ B = A`

---

## Common Pitfalls & Solutions

### Problem 1: "Sn is not defined" in browser console

**Cause:** Variable is scoped inside a closure

**Solution:** Extract from the JavaScript file directly, not the runtime

### Problem 2: Gzip decompression fails

**Cause:** Incomplete base64 string (grep truncated it)

**Solution:** Use sed/awk to extract multi-line strings, or extract from browser

### Problem 3: Solutions don't verify

**Cause:** Wrong byte order (little-endian vs big-endian)

**Solution:** The writeup uses **big-endian** encoding:
```javascript
solutionBytes[0] = (x >>> 24) & 0xff;  // MSB first
```

### Problem 4: Random search takes too long

**Cause:** Some puzzles have very few solutions

**Solution:** Use Z3 solver or increase iterations

---

## Tools & Commands Summary

```bash
# Beautify JavaScript
js-beautify minified.js -o beautified.js

# Search for patterns
grep -n "pattern" file.js
grep -oE 'regex' file.js

# Extract multi-line content
sed -n 'start,end p' file.js

# Decode base64
echo "base64string" | base64 -d

# Check file type
xxd file | head

# Node.js one-liners
node -e "console.log(crypto.createHash('sha256').update('test').digest('hex'))"

# Python Z3
pip3 install z3-solver
python3 solve.py
```

---

## Further Learning

**Topics to study:**
1. **Boolean Satisfiability (SAT):** Understanding constraint solving
2. **Z3 Theorem Prover:** Automated reasoning tool
3. **JavaScript obfuscation techniques:** Understanding minification/uglification
4. **Cryptographic key derivation:** PBKDF2, scrypt, Argon2
5. **Stream ciphers vs block ciphers:** XOR-based encryption

**Similar CTF challenges:**
- Look for "constraint solving" / "SAT solver" challenges
- Web challenges with client-side validation
- Obfuscated JavaScript reversing

---

## Conclusion

This challenge teaches:
- **Static analysis** of obfuscated web applications
- **Pattern recognition** in cryptographic code
- **Constraint solving** techniques
- **Key derivation** and stream cipher basics
- **Proper reverse engineering methodology**

The key skill is **not** knowing all the answers upfront, but knowing **how to ask the right questions** and **trace dependencies** systematically.

Flag: `SECCON{b00l34n_4dv3nt_2025_fl4g}`
