---
ctf: VUWCTF 2025
category: rev
difficulty: medium
points: 484
flag: "VuwCTF{m4th_when_95E68BBF_acr0ss_67_is_aw3s0ME}"
techniques: [constraint_solving, grid_puzzle, algebraic_solving]
tools: [python, z3]
---

# Math Solver

## Description
A stripped, statically-linked ELF binary containing an encrypted flag and a constraint-based math puzzle on an 11×11 grid.

## Solution

The binary contains a flag format string:
```
VuwCTF{m4th_when_%08lX_acr0ss_%02d_is_aw3s0ME}
```

### Grid Structure

An 11×11 grid with special byte values:
- `0xf9` = wall/boundary
- `0xfa` = empty cell (to be filled)
- `0xfb` = division operator (/)
- `0xfc` = multiplication operator (*)
- `0xfd` = subtraction operator (-)
- `0xfe` = addition operator (+)
- `0xff` = constraint marker

###Solving the Constraint System Algebraically

```python
x52 = 17 * 9           # = 153
x114 = 40 - 38         # = 2
x118 = 168 // 84       # = 2
x74 = x118 * 5         # = 10
x2 = 105 - 5           # = 100
x4 = x2 - 47           # = 53
x48 = x4 * 1           # = 53
x50 = x52 - x48        # = 100
x66 = 130 - 55         # = 75
x70 = x66 - 1          # = 74
x76 = 59 - 54          # = 5
x72 = x76 * x74        # = 50
x94 = x50 // x72       # = 2
x92 = 39 - x94         # = 37

# Compute FNV-1a hash of solved grid
h = 0x811c9dc5
for byte in grid:
    h = ((byte ^ h) * 0x1000193) & 0xffffffff

# Counter is grid[92] + 30 = 37 + 30 = 67
```

The solution yields:
- First parameter (hex): `95E68BBF`
- Second parameter (decimal): `67`

## Key Techniques
- Grid-based constraint puzzle solving
- Algebraic equation system solving
- Binary format string analysis
- Constraint satisfaction problem (CSP)
