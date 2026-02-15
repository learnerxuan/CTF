---
ctf: NullconCTF 2026
category: reverse
difficulty: hard
points: 400
flag: ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}
techniques:
  - code-coverage-analysis
  - xdebug-exploitation
  - collision-resolution
tools:
  - python
  - php
---

# Coverup

## Description

We are given:
- `output/encrypted_flag.txt`: `base64(ciphertext_bytes):sha1(ciphertext_bytes)`
- `output/coverage.json`: Xdebug code coverage while encrypting the real `flag.txt`
- `encrypt.php`: the encryption routine

**Goal:** recover the plaintext flag

## Solution

### 1. Understand the Encryption

Inside `FlagEncryptor::encrypt($plaintext)`:

- A 9-byte printable key is generated (not provided)
- For each plaintext byte `P[i]` with key byte `K[i % 9]`:
  1. A lookup function `M()` is applied to the key byte via a huge if/else chain: `K2 = M(K)`
  2. XOR with plaintext: `X = P ^ K2`
  3. Apply the same `M()` again to the XOR result: `C = M(X)`

The output bytes `C` are base64-encoded, and `sha1(C)` is appended.

**Important:** `M()` is **not injective** (many inputs map to the same output). So you cannot uniquely invert `C -> X` without extra information.

### 2. Use Coverage as an Oracle

`coverage.json` includes line coverage for the giant if/else chains:

- In the **first chain**, only the 9 `if ($keyChar == chr(N))` branches corresponding to the actual key bytes are hit ⇒ we recover the **set of key byte values**
- In the **second chain**, only branches for the actual `X = P ^ K2` values are hit ⇒ we recover the **set of X values** used during encryption

From the provided coverage, the executed key bytes are:
```
[49, 61, 65, 68, 86, 108, 111, 112, 122] → "1=ADVlopz"
```

### 3. Narrow Down X[i] Using Collisions + Coverage

We decode the base64 to get ciphertext bytes `C[i]`.

For each byte value `c`, compute all preimages `Pre(c) = { x | M(x) = c }` from `encrypt.php`.

Then for each position `i`:
```
X_candidates[i] = Pre(C[i]) ∩ X_set_from_coverage
```

In this challenge, **43/49 positions** become unique, and only **6 positions** have 2 candidates.

### 4. Recover Key Order and Plaintext

The key order matters (it repeats every 9 bytes), but coverage only gives the set of key bytes. We solve by backtracking with constraints:

- Plaintext is printable ASCII
- Prefix is `ENO{`
- Suffix is `}`

This yields a small number of plaintext candidates due to `M()` collisions; the intended one:

```
ENO{c0v3r4g3_l34k5_s3cr3t5_really_g00d_you_Kn0w?}
```

The recovered ordered key is: `=pVz1AlDo`

## Key Techniques

- Xdebug code coverage as a side-channel oracle
- Non-injective function collision resolution
- Constraint-based backtracking

