---
ctf: VUWCTF 2025
category: rev
difficulty: hard
points: 400
flag: "VuwCTF{0027094767331}"
techniques: [recursive_subtraction, self_execve, modular_arithmetic]
tools: [ghidra, python]
---

# String Inspector

## Description
A statically-linked binary that validates a flag by repeatedly calling itself via execve syscall, subtracting a constant each iteration.

## Solution

The binary expects a flag in format `VuwCTF{XXXXXXXXXXXXX}` (13 digits inside).

### Key Constants Found in Disassembly

- **Subtraction value**: 84673 (at 0x4017f8)
- **Target counter**: 319993 (checked at 0x401989)
- **Target remainder**: 42 (checked at 0x47f052)

### Algorithm

1. Extract 13-digit number from flag
2. Recursively subtract 84673 via self-execve calls
3. Accept when: `counter == 319993 AND remainder == 42`

### Solution

```python
# Reverse the algorithm:
# number = counter * subtraction_value + remainder
number = 319993 * 84673 + 42
# number = 27094767331
flag = f"VuwCTF{{00{number}}}"
```

## Key Techniques
- Static analysis of stripped binary
- Self- execve recursion pattern identification
- Reverse engineering modular arithmetic constraints
- Multi-iteration state reconstruction
