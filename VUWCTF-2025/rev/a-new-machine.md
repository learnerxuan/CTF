---
ctf: VUWCTF 2025
category: rev
difficulty: easy
points: 356
flag: "VuwCTF{ssslithering}"
techniques: [python_bytecode, python_3.14_alpha]
tools: [docker, python, dis]
---

# A New Machine

## Description
A Python bytecode file compiled with Python 3.14.0a4 (magic bytes `1d 0e 0d 0a`).

## Solution

The bytecode can't run on standard Python versions due to format changes between alpha and release. Built Python 3.14.0a4 from source in Docker to disassemble it.

### Flag Validation Logic Revealed

```python
def a(xs):
    return xs == 'lith'

class B:
    def __init__(self, s):
        self.s = s
    def __bool__(self):
        return sum(l == r for l, r in zip(map(lambda ch: ord(ch)**2, self.s),
                   (10201, 12996, 11025, 12100))) == 4

# Validation chain:
# i[0] == 'V'
# ord(i[1]) == 117  ('u')
# i[2:7] == 'wCTF{'
# i[7] == i[8] == i[9]  (3 identical chars)
# a(i[10:14])  → must be 'lith'
# B(i[14:18])  → must be 'erin' (sqrt of 10201,12996,11025,12100)
# i[19] == '}'
```
- 101² = e
- 114² = r  
- 105² = i
-110² = n

This gives: `"erin"`

**Combining**: `sss + lith + erin + g = "slithering"`

## Key Techniques
- Python bytecode version analysis
- Building Python alpha releases from source
- Bytecode disassembly with `dis` module
- Mathematical encoding reversal (squared ASCII values)
