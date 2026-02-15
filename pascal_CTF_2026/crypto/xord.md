---
ctf: PascalCTF 2026
category: crypto
difficulty: easy
points: 100
flag: pascalCTF{1ts_4lw4ys_4b0ut_x0r1ng_4nd_s33d1ng}
techniques:
  - xor-cipher
  - prng-seed-prediction
  - deterministic-randomness
tools:
  - python
---

# XorD

## Description

"I just discovered bitwise operators, so I guess 1 XOR 1 = 1?"

The challenge provides a Python encryption script and its output.

## Solution

Analyzing `xord.py`, the vulnerability is that `random.seed(1337)` uses a **hardcoded seed**. This means the random number sequence is completely deterministic and reproducible.

Since XOR is its own inverse (`A XOR B XOR B = A`), we can decrypt by:

1. Using the same seed (1337)
2. Generating the same random key sequence
3. XORing each encrypted byte with its corresponding random key

### Solution Code

```python
import random

# Read encrypted flag
with open('output.txt', 'r') as f:
    encrypted = bytes.fromhex(f.read().strip())

# Use same seed
random.seed(1337)

# Decrypt by XORing with same random sequence
flag = ''
for byte in encrypted:
    key = random.randint(0, 255)
    flag += chr(byte ^ key)

print(flag)
```

