---
ctf: ScarletCTF 2026
category: crypto
difficulty: hard
points: 500
flag: RUSEC{l1ar_li4R_pl4Nt5_f0r_h1r3_gqvhp9843}
techniques:
  - hash-collision
  - linear-cryptanalysis
  - kernel-computation
  - zkp-exploitation
tools:
  - python
  - sage
  - z3
---

# Coloring Fraud

## Description

**Points:** 500  
**Solves:** 0  
**Author:** ContronThePanda

"Now give it a try from the other side..."

We're given `chal.py` which implements a Zero-Knowledge Proof protocol for graph 3-coloring. This is the sequel to "Coloring Heist" where we were the verifier - **now we're the prover**.

## Solution

### Understanding the Challenge

The server asks us to prove we can 3-color K4 (the complete graph on 4 vertices). The protocol runs 128 rounds:

1. We send 4 commitments (one per vertex)
2. Server picks a random edge
3. We reveal colors/nonces for both endpoints
4. Server verifies: hashes match commitments AND colors differ

**The catch?** K4 is **not 3-colorable** - it needs 4 colors since every vertex is connected to every other vertex. We need to cheat by exploiting the hash function.

### The Vulnerability

The challenge uses a custom hash `xoo_fast_hash_256` instead of SHA256. For short messages (≤48 bytes), it uses `permute_fast` instead of `permute_full`.

**Notice what's missing compared to `permute_full`?** The **chi step** (the nonlinear `(a ^ ((~b) & c))` operation)!

This means `permute_fast` is a **completely linear function** over GF(2).

### Exploiting Linearity

For a 2-block message (41 bytes, padding to 48), the state evolution is affine.

Since `permute_fast` is affine (`f(x) = Mx + c`), for two messages to collide we need:

```
M·(block1 XOR block1') + M·(block2 XOR block2') = 0
```

Let `d1 = block1 XOR block1'` and `d2 = block2 XOR block2'`. Since M is invertible:

**Constraints on d1:**
1. `d1` must change the color byte (byte 0) to a valid difference (1, 2, or 3)
2. `(M·d1)[136:192] = 0` — padding bytes in block2 must be unchanged
3. `(M·d1)[192:256] = 0` — d2 can only affect state[0:6], not state[6:8]

This gives us **120 linear constraints on 192 bits** of d1. The kernel has **dimension 73**!

### Finding the Collision

We find a kernel vector with color delta = 3, giving us colors (1, 2):

```python
import hashlib

# Example collision (simplified)
msg1 = b'\x01' + nonce1  # Color 1
msg2 = b'\x02' + nonce2  # Color 2

# Both hash to the same value due to linear collision
assert xoo_fast_hash_256(msg1) == xoo_fast_hash_256(msg2)
```

Both messages hash to the same value but have different color bytes (1 vs 2).

### The Exploit

For any edge the server picks, we reveal `msg1` for one vertex and `msg2` for the other. They have different colors and matching hashes!

```python
# Pre-compute collision pair
collision_pair = find_collision()  # Returns (msg1, msg2) with same hash

# For any edge query
def answer_query(v1, v2):
    return {
        v1: collision_pair[0],  # Color 1
        v2: collision_pair[1]   # Color 2
    }
```

## Key Takeaways

- The "crypto" weakness was the missing nonlinear chi step in `permute_fast`
- Linear permutations allow algebraic collision finding via kernel computation
- With a 73-dimensional kernel and only needing color deltas 1/2/3, finding a valid collision was easy
- The challenge name "Fraud" hints at cheating the ZKP by exploiting hash collisions

