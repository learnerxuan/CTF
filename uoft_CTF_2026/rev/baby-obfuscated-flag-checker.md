---
ctf: UofTCTF 2026
category: rev
difficulty: easy
points: 100
flag: uoftctf{d1d_y0u_m0nk3Y_p4TcH_d3BuG_r3v_0r_0n3_sh07_th15_w17h_4n_1LM_XD???}
techniques:
  - python-deobfuscation
  - monkey-patching
  - dynamic-analysis
tools:
  - python3
---

# Baby (Obfuscated) Flag Checker

## Description

We are given a heavily obfuscated Python script that checks whether an input string is the correct flag. The logic is hidden inside a large state machine with junk arithmetic and confusing control flow.

**Hint:** Full deobfuscation is unnecessary.

## Key Observations

1. The program immediately exits unless the input length is exactly **74 characters**.
2. After the length check, the script performs many substring comparisons of the form: `s[a:b] == "expected_value"`
3. These comparisons are hidden inside the obfuscation, but at runtime they must still compare real strings.

So instead of reversing the state machine, we extract the expected substrings dynamically.

## Solution Strategy

We run the program with a partially-correct flag and patch the runtime so that whenever a substring comparison happens, we log:
- the slice being checked
- the expected value

We then reconstruct the flag incrementally.

## Example Extraction Script

This monkey-patches Python's string equality to log suspicious comparisons:

```python
import sys

# Monkey-patch string __eq__ to intercept comparisons
original_eq = str.__eq__

def logged_eq(self, other):
    result = original_eq(self, other)
    # Log any comparison involving our input
    if len(self) < 74 and len(other) < 74:
        print(f"Comparing: '{self}' == '{other}' -> {result}", file=sys.stderr)
    return result

str.__eq__ = logged_eq

# Run the obfuscated checker with dummy input
test_input = 'A' * 74
exec(open('checker.py').read())
```

**Usage:**
```bash
python dump_slices.py
```

By running the checker repeatedly and filling in discovered slices, the full flag can be reconstructed.

## Final Flag

```
uoftctf{d1d_y0u_m0nk3Y_p4TcH_d3BuG_r3v_0r_0n3_sh07_th15_w17h_4n_1LM_XD???}
```

## Key Techniques

- Monkey-patching for dynamic analysis
- Runtime interception of string comparisons
- Incremental flag reconstruction
- Avoiding static deobfuscation

