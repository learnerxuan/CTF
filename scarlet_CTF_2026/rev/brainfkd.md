---
ctf: ScarletCTF 2026
category: rev
difficulty: hard
points: 500
flag: RUSEC{g0d_im_s0_s0rry_for_th1s_p4in}
techniques:
  - brainfuck-analysis
  - per-position-mapping
  - brute-force-enumeration
tools:
  - python
  - custom-bf-interpreter
---

# brainfkd

## Description

A 64k Brainfuck program validates a 36-byte flag of the form `RUSEC{...}`. Initial tracing suggested comparing transformed input at `tape[257..292]` against a constant string at `tape[293..328]`, but solving on that block hits dead ends. The goal is to reverse the actual transformation and recover the flag.

## Solution

### Key Observations

1. **Per-position independence:** Each output position depends only on its corresponding input byte (no cross-position interaction). Flipping one input byte only changes the matching output cell.

2. **Hidden comparison target:** The program writes several constant ASCII blocks to the tape. The comparison target is **not** the `tape[293..328]` string; scanning the tape with zero input reveals another 36-byte printable window at `tape[473..508]` that fits the `RUSEC{}` shape under the per-position mappings.

### Approach

1. **Build mapping tables:** Create a fast BF runner and precompute `f_i(v)` for every position `i` (0–35) and byte `v` (0–255) by running the program with all inputs set to `v` and recording `tape[257..292]`.

2. **Find target window:** Run once with zero input, scan all 36-byte windows of the tape, and look for a window where the mappings can produce `RUSEC{` at positions 0–5 and `}` at position 35. Only `tape[473..508]` matches.

3. **Reverse each position:** For each position, pick any printable byte that maps to the target byte at `tape[473+i]`, enforcing the prefix/suffix constraints.

### Solver Code Structure

The solver (`solve_flag.c`) implements:

```c
// Build per-position mapping table
for (int i = 0; i < 36; i++) {
    for (int v = 0; v < 256; v++) {
        // Run BF with all inputs = v
        // Record output at tape[257+i]
        mapping[i][v] = output;
    }
}

// Find correct target window (tape[473..508])
// Reverse each position
for (int i = 0; i < 36; i++) {
    target = tape[473 + i];
    for (int c = 32; c < 127; c++) {  // Printable ASCII
        if (mapping[i][c] == target) {
            flag[i] = c;
            break;
        }
    }
}

// Enforce RUSEC{...} format
```

## Flag

```
RUSEC{g0d_im_s0_s0rry_for_th1s_p4in}
```

## Key Techniques

- **Brainfuck program analysis**
- **Per-position transformation mapping**
- **Tape memory scanning**
- **Constraint satisfaction** (enforcing flag format)
- **Brute-force enumeration** with precomputation

