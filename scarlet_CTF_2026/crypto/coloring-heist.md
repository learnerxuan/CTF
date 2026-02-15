---
ctf: ScarletCTF 2026
category: crypto
difficulty: medium
points: 444
flag: RUSEC{t0uhou_fum0_b4urs4k_orz0city_fn1x9fk3mdj1}
techniques:
  - graph-coloring
  - dsatur-algorithm
  - zkp-analysis
tools:
  - python
  - networkx
---

# Coloring Heist

## Description

**Points:** 444  
**Solves:** 23

We're given a zero-knowledge proof (ZKP) system for graph 3-coloring. The server has a secret 3-coloring of a graph with 1000 nodes and ~20k edges. Each round:

1. The server commits to the coloring using SHA256 with salts generated from an LCG
2. We can query one edge to see the colors and salts of those two nodes
3. We can guess the full coloring

The salts are generated using a truncated LCG (512-bit state, only top 128 bits revealed).

## Solution

### Initial (Wrong) Approach: Breaking the LCG

At first, I tried to break the truncated LCG using lattice attacks (Hidden Number Problem). The idea was:

- Collect multiple truncated LCG outputs from edge queries
- Use lattice reduction (LLL/BKZ) to recover the full LCG state
- Predict all salts and brute-force the 3 possible colors for each commit

However, this approach has a **fatal flaw**: the salts are shuffled using `random.shuffle()` before being assigned to nodes. Even if we recover the LCG state, we can't map salts to their corresponding nodes without also breaking Python's Mersenne Twister PRNG.

### The Real Insight: Unique 3-Coloring

The key observation is that the guess verification accepts **any coloring that matches the secret up to permutation of colors**.

This means: if the graph has a **unique 3-coloring** (up to relabeling), we can simply compute it from `graph.txt` and submit it directly!

With 1000 nodes and ~20k edges, the graph is highly constrained. Using the **DSATUR algorithm** (greedy coloring with maximum saturation heuristic), we can solve it almost instantly.

### Final Solution

```python
import networkx as nx

# Load graph
G = nx.read_edgelist('graph.txt', nodetype=int)

# DSATUR algorithm (greedy coloring)
coloring = nx.coloring.greedy_color(G, strategy='DSATUR')

# Submit coloring
# (colors are 0, 1, 2)
answer = [coloring[i] for i in range(len(G.nodes()))]
print(answer)
```

**The lesson:** sometimes the "crypto" in a crypto challenge is a red herring. Understanding what the verification actually checks can reveal a much simpler path to the flag.

## Key Techniques

- Graph 3-coloring algorithms
- DSATUR (Degree of Saturation) heuristic
- ZKP protocol analysis
- Recognizing when the "obvious" attack is misdirection

