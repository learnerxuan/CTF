# UofTCTF 2025 - Guess The Number Writeup

**Challenge**: Guess The Number
**Category**: Misc
**Flag**: `uoftctf{h0w_did_y0u_gu3ss_7h3_numb3r}`

---

## 📋 Table of Contents

1. [Challenge Description](#challenge-description)
2. [Initial Analysis](#initial-analysis)
3. [The Problem](#the-problem)
4. [Key Concepts](#key-concepts)
5. [Common Confusions & Clarifications](#common-confusions--clarifications)
6. [The Solution: Timing Side-Channel Attack](#the-solution-timing-side-channel-attack)
7. [Building The Magic Expression](#building-the-magic-expression)
8. [Running The Exploit](#running-the-exploit)
9. [Complete Exploit Code](#complete-exploit-code)
10. [Key Takeaways](#key-takeaways)

---

## 🎯 Challenge Description

**Challenge Files**: `chall.py`

**Server**: `nc 35.231.13.90 5000`

**The Setup:**
- Server picks a random number `x` between `0` and `2^100` (that's 1,267,650,600,228,229,401,496,703,205,376)
- You get **50 queries** to ask questions about the number
- Each query is a mathematical expression that the server evaluates
- Server responds with **"Yes!"** (truthy) or **"No!"** (falsy)
- After 50 queries, you must guess the exact number
- Correct guess = FLAG!

---

## 🔍 Initial Analysis

### Challenge Code Structure

```python
#!/usr/local/bin/python3
import random
from ast import literal_eval

MAX_NUM = 1<<100  # 2^100
QUOTA = 50        # 50 queries

def evaluate(exp, x):
    # Evaluates expressions like {'op': '>', 'arg1': 'x', 'arg2': 100}
    # Supports: and, or, not, >, >=, <, <=, +, -, *, /, **, %
    ...

x = random.randint(0, MAX_NUM)
for i in range(QUOTA):
    expression = literal_eval(input(f"Input your expression ({i}/{QUOTA}): "))
    if bool(evaluate(expression, x)):
        print("Yes!")
    else:
        print("No!")

guess = int(input("Guess the number: "))
if guess == x:
    print("Yay you won! Here is the flag: ")
    print(open("flag.txt", 'r').read())
```

### Key Observations

1. **Input format**: Must be valid Python literal (dict, not arbitrary code)
2. **Expression structure**: Dictionary with `'op'`, `'arg1'`, `'arg2'` keys
3. **The oracle**: `evaluate()` function answers yes/no questions
4. **Operators available**: Arithmetic, comparison, and logical operators

---

## ❌ The Problem

### Why Binary Search Fails

**Binary search approach:**
- Each query divides range in half
- Query 1: 2^100 → 2^99
- Query 2: 2^99 → 2^98
- Query N: 2^(100-N)
- **Need 100 queries to reach 2^0 = 1**
- **We only have 50 queries!** ❌

**The math:**
```
log₂(2^100) = 100 queries needed
Available: 50 queries
Shortfall: 50 queries
```

### The Challenge

**How do you get 100 bits of information from only 50 queries?**

Answer: **Get 2 bits per query instead of 1!**

---

## 🔑 Key Concepts

### 1. What is an Oracle?

An **oracle** is a system that answers questions about a secret without revealing it directly.

**Example:**
- Secret number: 73 (hidden from you)
- You ask: "Is the secret > 50?"
- Oracle: "Yes!" (because 73 > 50 is TRUE)
- You ask: "Is the secret < 50?"
- Oracle: "No!" (because 73 < 50 is FALSE)

**In this challenge**: The `evaluate()` function is your oracle.

---

### 2. What is a Side-Channel?

A **side-channel** is unintended information leakage through indirect means.

**Examples in real world:**
- **Timing**: How long a password check takes
- **Power**: How much electricity a chip uses
- **Sound**: What sounds a keyboard makes
- **EM Radiation**: Electromagnetic signals from hardware

**In this challenge**:
- **Intended channel**: Yes/No response (1 bit)
- **Side-channel**: Timing - Fast/Slow (1 extra bit!)
- **Total**: 2 bits per query!

---

### 3. Short-Circuit Evaluation

This is **THE KEY** to the entire attack!

Python's `OR` and `AND` operators can **skip** evaluating parts of expressions:

#### OR Operator Behavior:

```python
True  OR <anything>  → Returns True IMMEDIATELY (doesn't evaluate <anything>)
False OR <something> → MUST evaluate <something> to know the result
```

**Example:**
```python
def slow_function():
    time.sleep(2)  # Takes 2 seconds
    return True

# Case 1: Short-circuits (FAST)
result = True OR slow_function()
# Python sees "True OR ...", knows result is True, never calls slow_function()
# Time: 0 seconds ⚡

# Case 2: Must evaluate (SLOW)
result = False OR slow_function()
# Python sees "False OR ...", must check second part, calls slow_function()
# Time: 2 seconds 🐌
```

#### AND Operator Behavior:

```python
False AND <anything>  → Returns False IMMEDIATELY (doesn't evaluate <anything>)
True  AND <something> → MUST evaluate <something> to know the result
```

**The Critical Insight:**
> By measuring HOW LONG it takes to get an answer, you can tell WHETHER the second part was evaluated! This is the timing side-channel!

---

### 4. Timing Attack

**Definition**: Measuring execution time to infer secret information.

**Our Attack:**
- Create expressions with expensive operations (`2^(2^25)`)
- Expensive operation takes ~1-2 seconds
- Normal operations take ~0.2 seconds
- **Measure the time difference to extract extra information!**

---

## 🤔 Common Confusions & Clarifications

### ❓ Confusion 1: "What do 'Yes!' and 'No!' mean?"

**WRONG Understanding:**
> "The server says 'Yes!' when I've guessed the correct number"

**CORRECT Understanding:**
> "Yes!" means your TRUE/FALSE expression evaluated to TRUE
> "No!" means your TRUE/FALSE expression evaluated to FALSE

**Example:**
```python
Secret = 73

Query: {'op': '>', 'arg1': 'x', 'arg2': 50}  # Is x > 50?
Evaluation: 73 > 50 = TRUE
Response: "Yes!"

Query: {'op': '<', 'arg1': 'x', 'arg2': 50}  # Is x < 50?
Evaluation: 73 < 50 = FALSE
Response: "No!"
```

You're **NOT guessing the number directly**. You're asking questions to **narrow down the range**!

---

### ❓ Confusion 2: "Why won't my expression work?"

**Common errors when manually connecting:**

#### ❌ Wrong Format #1: Using Python code
```python
# This DOES NOT WORK:
Is x > 50?
x < 1
OR(x < 50, AND(...))
```

#### ❌ Wrong Format #2: Multi-line with comments
```python
# This DOES NOT WORK (comments not allowed):
{
    'op': 'or',
    'arg1': {...},  # This is Q1
    'arg2': {...}   # This is Q2
}
```

#### ❌ Wrong Format #3: Missing brackets
```python
# This DOES NOT WORK (missing opening {):
'op': 'or', 'arg1': {...}, 'arg2': {...}
```

#### ✅ CORRECT Format:
```python
# Single line, no comments, valid Python dict:
{'op': '>', 'arg1': 'x', 'arg2': 50}
```

---

### ❓ Confusion 3: "Short-circuit evaluation - don't both parts need to be evaluated?"

**The confusion:**
> "I thought with `1 + 1`, both numbers must be evaluated. So why doesn't OR/AND evaluate everything?"

**The clarification:**
> **OR and AND are SPECIAL operators** - they're different from arithmetic!

**Arithmetic (`+`, `-`, `*`):**
```python
1 + slow_function()
# Must evaluate both sides to compute the sum
```

**Logical (`OR`, `AND`):**
```python
True OR slow_function()
# Does NOT need to evaluate slow_function()!
# Already knows result is True from first part
```

**Visual example:**
```
Expression: False OR slow_function()

Step 1: Check first part → False
Step 2: OR needs at least one True, must check second part
Step 3: Call slow_function() ← Takes 2 seconds!
Result: Whatever slow_function() returns

---

Expression: True OR slow_function()

Step 1: Check first part → True
Step 2: OR already has a True, stop here!
Result: True (never evaluated slow_function())
```

**This is NOT about the final result being true/false. It's about HOW MUCH of the expression gets evaluated!**

---

### ❓ Confusion 4: "How can the server return 4 results?"

**The confusion:**
> "The server only replies 'Yes!' or 'No!'. How do you get 4 different results?"

**The clarification:**
> The server DOES only return ONE text response, but we measure TWO things!

**What you receive from each query:**

| Information | Source | Values |
|-------------|--------|--------|
| Text Response | Server replies | "Yes!" or "No!" |
| Time Taken | You measure with timer | Fast (~0.2s) or Slow (~2s) |

**These COMBINE to give 4 possibilities:**

| Response | Timing | Combined State | Meaning |
|----------|--------|----------------|---------|
| "Yes!" | Fast (0.2s) | State 1 | Quarter 1 |
| "No!" | Fast (0.2s) | State 2 | Quarter 2 |
| "Yes!" | Slow (2s) | State 3 | Quarter 3 |
| "No!" | Slow (2s) | State 4 | Quarter 4 |

**It's not 4 separate responses - it's 2 pieces of information (text + time) that combine!**

---

## 💡 The Solution: Timing Side-Channel Attack

### The Strategy: Quaternary Search

**Binary Search**: Divide into 2 parts → Need 100 queries
**Quaternary Search**: Divide into 4 parts → Need 50 queries ✅

**The Math:**
```
Binary:      log₂(2^100) = 100 queries
Quaternary:  log₄(2^100) = log₄(2^100) = 100/2 = 50 queries ✓

Why? 4 = 2², so each query extracts 2 bits instead of 1
50 queries × 2 bits = 100 bits = enough for 2^100 space!
```

---

### How Quaternary Search Works

**Divide the range into 4 quarters:**

```
Current range: [min, max]

Q1: [min,        min + 25%)  Quarter 1
Q2: [min + 25%,  min + 50%)  Quarter 2
Q3: [min + 50%,  min + 75%)  Quarter 3
Q4: [min + 75%,  max]        Quarter 4
```

**Create an expression that:**
1. Returns different Yes/No for different quarters
2. Takes different time (Fast/Slow) for different quarters
3. The combination tells you EXACTLY which quarter!

---

### The Magic Expression (High-Level)

```python
OR(
    x < Q1_END,                    # Check Q1
    AND(
        x >= Q2_END,               # Check Q2+
        2^(2^25),                  # SLOW OPERATION!
        x < Q3_END                 # Check Q3
    )
)
```

**Translation to English:**
```
Is (x in Q1) OR ((x in Q2+) AND (slow_operation) AND (x in Q3))?
```

---

### Execution Flow for Each Quarter

#### 🔵 Secret in Q1: [min, Q1_END)

```
Evaluate: OR(x < Q1_END, ...)
          ↓
Check: x < Q1_END? → TRUE
          ↓
OR short-circuits → Return TRUE immediately
          ↓
Response: "Yes!" + Time: 0.2s (FAST)
```

#### 🟢 Secret in Q2: [Q1_END, Q2_END)

```
Evaluate: OR(x < Q1_END, AND(x >= Q2_END, ...))
          ↓
Check: x < Q1_END? → FALSE
          ↓
Must check AND part...
          ↓
Check: x >= Q2_END? → FALSE
          ↓
AND short-circuits → Return FALSE immediately
          ↓
Response: "No!" + Time: 0.2s (FAST)
```

#### 🟡 Secret in Q3: [Q2_END, Q3_END)

```
Evaluate: OR(x < Q1_END, AND(x >= Q2_END, 2^(2^25), x < Q3_END))
          ↓
Check: x < Q1_END? → FALSE
          ↓
Must check AND part...
          ↓
Check: x >= Q2_END? → TRUE
          ↓
Must evaluate next part...
          ↓
Compute: 2^(2^25) ← TAKES 2 SECONDS!
          ↓
Check: x < Q3_END? → TRUE
          ↓
AND result: TRUE AND TRUE AND TRUE = TRUE
          ↓
Response: "Yes!" + Time: 2s (SLOW)
```

#### 🔴 Secret in Q4: [Q3_END, max]

```
Evaluate: OR(x < Q1_END, AND(x >= Q2_END, 2^(2^25), x < Q3_END))
          ↓
Check: x < Q1_END? → FALSE
          ↓
Must check AND part...
          ↓
Check: x >= Q2_END? → TRUE
          ↓
Must evaluate next part...
          ↓
Compute: 2^(2^25) ← TAKES 2 SECONDS!
          ↓
Check: x < Q3_END? → FALSE
          ↓
AND result: TRUE AND TRUE AND FALSE = FALSE
          ↓
Response: "No!" + Time: 2s (SLOW)
```

---

### Decision Table

| Quarter | Secret Range | Response | Timing | Logic |
|---------|--------------|----------|--------|-------|
| **Q1** | [min, Q1_END) | "Yes!" | Fast (0.2s) | `x < Q1_END` → OR short-circuits |
| **Q2** | [Q1_END, Q2_END) | "No!" | Fast (0.2s) | `x < Q1_END` fails, `x >= Q2_END` fails → AND short-circuits |
| **Q3** | [Q2_END, Q3_END) | "Yes!" | Slow (2s) | Must compute slow op, `x < Q3_END` succeeds |
| **Q4** | [Q3_END, max] | "No!" | Slow (2s) | Must compute slow op, `x >= Q3_END` fails |

---

### Complete Attack Flow

**Initial State:**
```
Range: [0, 2^100]
Size: 1,267,650,600,228,229,401,496,703,205,376
```

**Query 1:**
```
Quarters: Q1=[0, 2^98), Q2=[2^98, 2^99), Q3=[2^99, 2^99.58), Q4=[2^99.58, 2^100]
Send magic expression
Receive: "Yes!" in 1.8s (SLOW)
Decode: Quarter 3
New range: [2^99, 2^99.58)
New size: 2^100 / 4 = 2^98
```

**Query 2:**
```
Range: [2^99, 2^99.58)
Quarters: [Q1, Q2, Q3, Q4] of the new range
Send magic expression
Receive: "No!" in 0.2s (FAST)
Decode: Quarter 2
New size: 2^98 / 4 = 2^96
```

**... Continue for 50 queries ...**

**Query 50:**
```
Range size: 2^100 / (4^50) = 2^100 / 2^100 = 1
Found exact number!
```

---

## 🔧 Building The Magic Expression

Let's build the expression **step by step** from simple to complex.

### Step 1: Simple Comparison

**Goal**: Check if x > 50

```python
{'op': '>', 'arg1': 'x', 'arg2': 50}
```

**Translation**: "Is x > 50?"

---

### Step 2: The Slow Operation

**Goal**: Create something that takes ~2 seconds

```python
{'op': '**', 'arg1': 2, 'arg2': 33554432}
```

**Translation**: "2^33554432" (2 to the power of 2^25)

**Why this number?** 2^25 = 33,554,432. Computing 2^(2^25) is astronomically expensive!

---

### Step 3: Nested AND (Inner)

**Goal**: Combine slow operation with a check

```python
{
    'op': 'and',
    'arg1': {'op': '**', 'arg1': 2, 'arg2': 33554432},  # Slow operation
    'arg2': {'op': '<', 'arg1': 'x', 'arg2': 75}        # Check x < 75
}
```

**Translation**: "(slow_operation) AND (x < 75)"

---

### Step 4: Nested AND (Outer)

**Goal**: Check if x >= 50 before doing slow operation

```python
{
    'op': 'and',
    'arg1': {'op': '>=', 'arg1': 'x', 'arg2': 50},      # x >= 50?
    'arg2': {
        'op': 'and',
        'arg1': {'op': '**', 'arg1': 2, 'arg2': 33554432},
        'arg2': {'op': '<', 'arg1': 'x', 'arg2': 75}
    }
}
```

**Translation**: "(x >= 50) AND ((slow_operation) AND (x < 75))"

---

### Step 5: Complete OR Expression

**Goal**: Add the Q1 check at the top level

```python
{
    'op': 'or',
    'arg1': {'op': '<', 'arg1': 'x', 'arg2': 25},       # Q1: x < 25?
    'arg2': {
        'op': 'and',
        'arg1': {'op': '>=', 'arg1': 'x', 'arg2': 50},  # Q2+: x >= 50?
        'arg2': {
            'op': 'and',
            'arg1': {'op': '**', 'arg1': 2, 'arg2': 33554432},  # SLOW!
            'arg2': {'op': '<', 'arg1': 'x', 'arg2': 75}        # Q3: x < 75?
        }
    }
}
```

**Translation**: "(x < 25) OR ((x >= 50) AND ((slow_operation) AND (x < 75)))"

---

### Visual Tree Structure

```
                        OR
                       /  \
                      /    \
                 (x < 25)  AND
                 [Q1]      /  \
                          /    \
                   (x >= 50)   AND
                   [Q2+ gate]  /  \
                              /    \
                        (2^big)   (x < 75)
                        [SLOW]    [Q3]
```

**Reading the tree:**
- If `x < 25`: Left branch is TRUE → OR returns TRUE immediately (FAST)
- If `x >= 25 and x < 50`: Right AND's first check fails → Returns FALSE quickly (FAST)
- If `x >= 50 and x < 75`: Right AND evaluates slow operation → Returns TRUE slowly (SLOW)
- If `x >= 75`: Right AND evaluates slow operation → Returns FALSE slowly (SLOW)

---

### Dynamic Expression (For Any Range)

```python
def build_magic_expression(min_val, max_val):
    # Calculate quarter boundaries
    q1_end = min_val + (max_val - min_val) // 4
    q2_end = min_val + 2 * (max_val - min_val) // 4
    q3_end = min_val + 3 * (max_val - min_val) // 4

    # Build the expression
    expr = {
        'op': 'or',
        'arg1': {'op': '<', 'arg1': 'x', 'arg2': q1_end},
        'arg2': {
            'op': 'and',
            'arg1': {'op': '>=', 'arg1': 'x', 'arg2': q2_end},
            'arg2': {
                'op': 'and',
                'arg1': {'op': '**', 'arg1': 2, 'arg2': int(2**25)},
                'arg2': {'op': '<', 'arg1': 'x', 'arg2': q3_end}
            }
        }
    }
    return expr
```

---

## 🚀 Running The Exploit

### Method 1: Manual Testing (Educational)

Connect to the server:
```bash
nc 35.231.13.90 5000
```

Send a simple test expression (one line, no comments):
```python
{'op': '>', 'arg1': 'x', 'arg2': 500000000}
```

Server will reply "Yes!" or "No!" indicating if x > 500000000.

---

### Method 2: Run The Exploit Script (Automated)

```bash
cd /home/xuan/uoft_CTF2025/guess_the_number
python3 solve_quaternary.py
```

**Expected output:**
```
[x] Opening connection to 35.231.13.90 on port 5000
[+] Opening connection to 35.231.13.90 on port 5000: Done
0 1267650600228229401496703205376 1267650600228229401496703205376
1.9699385166168213 b' (0/50): Yes!'
...
[+] Final answer: 1108002945390720362554083000911
Yay you won! Here is the flag:
uoftctf{h0w_did_y0u_gu3ss_7h3_numb3r}
```

---

## 📝 Complete Exploit Code

### `solve_quaternary.py`

```python
#!/usr/bin/env python3
from pwn import *
import time

MAX_NUM = 1<<100
QUOTA = 50

r = remote("35.231.13.90", 5000)

min = 0
max = MAX_NUM

for j in range(QUOTA):
    print(min, max, max-min)

    # Build the magic expression
    expr = {
        "op": "or",
        "arg1": {"op": "<", "arg1": "x", "arg2": (min + (max-min)//4)},
        "arg2": {
            "op": "and",
            "arg1": {"op": ">=", "arg1": "x", "arg2": (min + 2*(max-min)//4)},
            "arg2": {
                "op": "and",
                "arg1": {"op": "**", "arg1": 2, "arg2": int(2**25)},
                "arg2": {"op": "<", "arg1": "x", "arg2": (min + 3*(max-min)//4)}
            }
        }
    }

    # Send and measure timing
    t1 = time.time()
    r.sendlineafter(b'Input your expression', str(expr))
    res = r.recvuntil(b'!')
    t2 = time.time()

    print(t2 - t1, res)

    # Decode which quarter based on response + timing
    if b'Yes' in res:
        if t2 - t1 < 0.3:
            # Q1: Yes + Fast
            max = (min + (max-min)//4) - 1
        else:
            # Q3: Yes + Slow
            min = (min + 2*(max-min)//4)
            max = (min + 3*(max-min)//4) - 1
    else:
        if t2 - t1 < 0.3:
            # Q2: No + Fast
            min = (min + (max-min)//4)
            max = (min + 2*(max-min)//4) - 1
        else:
            # Q4: No + Slow
            min = min + (3*(max-min)//4)

print(f"\n[+] Final answer: {min}")
print(f"[+] Range: [{min}, {max}], size: {max-min}")

r.sendlineafter(b'number:', str(min))
print(r.recvall().decode())
```

---

### Alternative: Bit Extraction with Timing

Another approach extracts 2 bits per query using timing on individual bit checks:

```python
#!/usr/bin/env python3
from pwn import *
import time

def make_bit_check(bit_pos):
    """Check if bit at position bit_pos is set"""
    return {
        "op": ">=",
        "arg1": {"op": "%", "arg1": {"op": "/", "arg1": "x", "arg2": 2**bit_pos}, "arg2": 2},
        "arg2": 1
    }

def make_timing_expr(bit_a_pos, bit_b_pos):
    """
    Extract 2 bits using timing side-channel:
    - bit_a from response (Yes/No)
    - bit_b from timing (Fast/Slow)
    """
    a_expr = make_bit_check(bit_a_pos)
    b_expr = make_bit_check(bit_b_pos)
    slow_expr = {"op": "**", "arg1": 3, "arg2": 1000000}

    # OR(NOT(b_expr), slow_expr)
    # If b=0: NOT(b)=True, short-circuits (fast)
    # If b=1: NOT(b)=False, evaluates slow_expr (slow)
    slow_if_b = {
        "op": "or",
        "arg1": {"op": "not", "arg1": b_expr},
        "arg2": slow_expr
    }

    # AND(slow_if_b, a_expr)
    return {"op": "and", "arg1": slow_if_b, "arg2": a_expr}

conn = remote("35.231.13.90", 5000)
bits = [0] * 100

for i in range(50):
    expr = make_timing_expr(2*i, 2*i+1)
    conn.recvuntil(b": ")

    start = time.time()
    conn.sendline(str(expr).encode())
    response = conn.recvline().decode()
    elapsed = time.time() - start

    bits[2*i] = 1 if "Yes" in response else 0
    bits[2*i+1] = 1 if elapsed > 0.4 else 0

    print(f"Query {i+1}/50: bit[{2*i}]={bits[2*i]} (response), bit[{2*i+1}]={bits[2*i+1]} (timing={elapsed:.3f}s)")

x = sum(bits[i] << i for i in range(100))
print(f"\n[+] Reconstructed number: {x}")

conn.recvuntil(b": ")
conn.sendline(str(x).encode())
print(conn.recvall().decode())
```

---

## 🎓 Key Takeaways

### Security Lessons

1. **Timing attacks are real** - Used against cryptographic systems, password checks, etc.
2. **Side-channels matter** - Information leaks through unintended channels
3. **Constant-time algorithms** - Designed to prevent timing attacks
4. **Defense in depth** - Multiple layers of security needed

### CTF Techniques

1. **Think outside the box** - The intended limitation (50 queries) can be bypassed
2. **Information theory** - Understanding bits, entropy, and information content
3. **Side-channel exploitation** - Looking beyond the obvious interface
4. **Python internals** - Understanding how OR/AND actually work

### Programming Concepts

1. **Short-circuit evaluation** - OR/AND operators optimize by skipping unnecessary checks
2. **Big O notation** - log₄(N) vs log₂(N) makes a huge difference
3. **Dictionary structures** - Representing complex expressions as nested dicts
4. **Timing measurements** - `time.time()` for performance profiling

---

## 📚 References

- **Short-circuit evaluation**: https://en.wikipedia.org/wiki/Short-circuit_evaluation
- **Timing attacks**: https://en.wikipedia.org/wiki/Timing_attack
- **Side-channel attacks**: https://en.wikipedia.org/wiki/Side-channel_attack
- **Information theory**: https://en.wikipedia.org/wiki/Information_theory

---

## 🏆 Summary

**Challenge**: Guess a random number from 0 to 2^100 with only 50 queries

**Problem**: Binary search needs 100 queries, we only have 50

**Solution**: Use timing side-channel to extract 2 bits per query (response + timing)

**Technique**: Quaternary search with short-circuit evaluation and expensive operations

**Result**: 50 queries × 2 bits = 100 bits = exact number found!

**Flag**: `uoftctf{h0w_did_y0u_gu3ss_7h3_numb3r}`

---
