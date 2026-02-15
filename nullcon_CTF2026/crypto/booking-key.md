---
ctf: NullconCTF 2026
category: crypto
difficulty: medium
points: 200
flag: ENO{y0u_f1nd_m4ny_th1ng5_in_w0nd3r1and}
techniques:
  - book-cipher
  - brute-force-starting-position
  - constraint-solving
tools:
  - python
---

# Booking Key

## Description

A book cipher challenge using an abridged Alice's Adventures in Wonderland (Project Gutenberg #19033, "Storyland" series). The server encrypts a random 32-character password using a book cipher and sends the ciphertext (list of step counts). We must decrypt 3 passwords correctly to get the flag.

The encryption works by walking through the book text character-by-character: for each password character, it counts how many steps forward from the current position until that character is found. The count is appended to the cipher, and the cursor stays at the found position.

## Solution

### Key Observations

1. The book text is from PG #19033, including the "Produced by..." credit header and a trailing newline (total **53597 chars**)
2. Given the cipher (list of offsets), we can try all possible starting positions and decrypt
3. Most starting positions produce non-letter characters (spaces, punctuation), so we filter for candidates where all 32 characters are ASCII letters

### Distinguishing True Password

To distinguish the correct candidate from false positives, we use two heuristics:

1. **Violation count:** For each step, check if the target character appears earlier than where the cipher says. The true password has **0 violations**
2. **Uppercase ratio:** Random passwords from 51 chars (25 upper, 26 lower) should have ~49% uppercase. False positives tend to land on common lowercase English text

### Algorithm

```python
# For each starting position (0 to len(BOOK)-1)
for start_pos in range(len(BOOK)):
    # Compute cumulative sums of cipher values to get 32 character positions
    positions = []
    pos = start_pos
    for offset in cipher:
        pos += offset
        positions.append(pos)
    
    # Filter: all positions must be letters
    candidate = ''.join(BOOK[p] for p in positions)
    if not candidate.isalpha():
        continue
    
    # Score: count violations and uppercase ratio
    violations = count_violations(candidate, cipher, start_pos)
    uppercase_ratio = sum(c.isupper() for c in candidate) / len(candidate)
    
    # Pick candidate with 0 violations and realistic uppercase ratio
    if violations == 0 and 0.4 < uppercase_ratio < 0.6:
        return candidate
```

