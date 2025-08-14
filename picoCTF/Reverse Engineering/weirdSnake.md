# picoCTF weirdSnake - Python Bytecode Reverse Engineering

## Challenge Information
- **Name:** weirdSnake
- **Category:** Reverse Engineering
- **Description:** I have a friend that enjoys coding and he hasn't stopped talking about a snake recently. He left this file on my computer and dares me to uncover a secret phrase from it. Can you assist?
- **Files:** `snake` (Python bytecode disassembly)

## Table of Contents
1. [Initial Analysis](#initial-analysis)
2. [Understanding Python Bytecode](#understanding-python-bytecode)
3. [Reconstructing the Algorithm](#reconstructing-the-algorithm)
4. [Solution](#solution)
5. [Key Concepts](#key-concepts)
6. [Tools and Techniques](#tools-and-techniques)

## Initial Analysis

### File Examination
```bash
┌──(xuan㉿kali)-[~/random]
└─$ file snake 
snake: ASCII text
```

The file contains Python bytecode disassembly - not regular Python source code, but the low-level instructions Python uses internally.

### What is Python Bytecode?

When Python code is executed, it's first compiled to bytecode - an intermediate representation that the Python Virtual Machine (PVM) executes. This challenge gives us the disassembled bytecode, and we need to reverse engineer what the original code does.

## Understanding Python Bytecode

### Key Instructions in This Challenge

| Instruction | Description |
|------------|-------------|
| `LOAD_CONST` | Push a constant value onto the stack |
| `LOAD_NAME` | Load a variable's value onto the stack |
| `STORE_NAME` | Store the top stack value into a variable |
| `BINARY_ADD` | Pop two values, add them, push result |
| `BINARY_XOR` | Pop two values, XOR them, push result |
| `BUILD_LIST` | Create a list from stack items |
| `CALL_FUNCTION` | Call a function with arguments from stack |

### Stack-Based Execution

Python bytecode uses a stack-based virtual machine:
```
LOAD_CONST 5    # Stack: [5]
LOAD_CONST 3    # Stack: [5, 3]
BINARY_ADD      # Stack: [8]  (5 + 3)
STORE_NAME x    # Stack: []   (x = 8)
```

## Reconstructing the Algorithm

### Step 1: Building the Input List (Lines 1-82)

The bytecode loads 40 constants and builds a list:

```python
# Extracting the constants being loaded
input_list = [
    4, 54, 41, 0, 112, 32, 25, 49, 33, 3, 
    0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 
    7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 
    43, 102, 126, 92, 0, 16, 58, 41, 89, 78
]
```

### Step 2: Building the Key String (Lines 84-118)

Let's trace through the key construction:

```
Line 84-86:  key_str = 'J'
Line 88-94:  LOAD_CONST '_', LOAD_NAME key_str, BINARY_ADD
             → '_' + 'J' = '_J'
             key_str = '_J'
Line 96-102: LOAD_NAME key_str, LOAD_CONST 'o', BINARY_ADD
             → '_J' + 'o' = '_Jo'
             key_str = '_Jo'
Line 104-110: LOAD_NAME key_str, LOAD_CONST '3', BINARY_ADD
             → '_Jo' + '3' = '_Jo3'
             key_str = '_Jo3'
Line 112-118: LOAD_CONST 't', LOAD_NAME key_str, BINARY_ADD
             → 't' + '_Jo3' = 't_Jo3'
             key_str = 't_Jo3'
```

**Final key_str: `'t_Jo3'`**

### Step 3: Converting Key to ASCII Values (Lines 120-132)

The first list comprehension:
```python
# Disassembly shows: ord(char) for each char
key_list = [ord(char) for char in key_str]
# key_list = [116, 95, 74, 111, 51]  # ASCII values of 't_Jo3'
```

### Step 4: Extending the Key (Lines 134-160)

```python
while len(key_list) < len(input_list):
    key_list.extend(key_list)
```

This repeats the key to match the input length:
```
Original: [116, 95, 74, 111, 51]
Extended: [116, 95, 74, 111, 51, 116, 95, 74, 111, 51, 116, 95, ...]
```

### Step 5: XOR Decryption (Lines 162-180)

The second list comprehension performs XOR:
```python
result = [a ^ b for a, b in zip(input_list, key_list)]
```

### Step 6: Converting to Text (Lines 182-196)

```python
result_text = ''.join(map(chr, result))
```

## Solution

### Complete Solution Script

```python
#!/usr/bin/env python3
"""
weirdSnake Challenge Solver
Reverses the XOR encryption from Python bytecode
"""

def solve_weird_snake():
    # Step 1: The encrypted data (from bytecode constants)
    input_list = [
        4, 54, 41, 0, 112, 32, 25, 49, 33, 3, 
        0, 0, 57, 32, 108, 23, 48, 4, 9, 70, 
        7, 110, 36, 8, 108, 7, 49, 10, 4, 86, 
        43, 102, 126, 92, 0, 16, 58, 41, 89, 78
    ]
    
    # Step 2: Reconstruct the key string
    # Following the exact bytecode operations
    key_str = 'J'
    key_str = '_' + key_str  # '_J'
    key_str = key_str + 'o'  # '_Jo'
    key_str = key_str + '3'  # '_Jo3'
    key_str = 't' + key_str  # 't_Jo3'
    
    print(f"[+] Key string: '{key_str}'")
    
    # Step 3: Convert key to ASCII values
    key_list = [ord(char) for char in key_str]
    print(f"[+] Key ASCII values: {key_list}")
    
    # Step 4: Extend key to match input length
    original_key_len = len(key_list)
    while len(key_list) < len(input_list):
        key_list.extend(key_list[:original_key_len])
    key_list = key_list[:len(input_list)]  # Trim to exact length
    
    print(f"[+] Extended key length: {len(key_list)}")
    
    # Step 5: XOR decryption
    result = [a ^ b for a, b in zip(input_list, key_list)]
    
    # Step 6: Convert to text
    result_text = ''.join(map(chr, result))
    
    print(f"[+] Decrypted flag: {result_text}")
    return result_text

if __name__ == "__main__":
    print("=== weirdSnake Challenge Solver ===\n")
    flag = solve_weird_snake()
    print(f"\n[✓] FLAG: {flag}")
```

### Running the Solution

```bash
┌──(xuan㉿kali)-[~/random]
└─$ python3 solve_snake.py
=== weirdSnake Challenge Solver ===

[+] Key string: 't_Jo3'
[+] Key ASCII values: [116, 95, 74, 111, 51]
[+] Extended key length: 40
[+] Decrypted flag: picoCTF{N0t_sO_coNfus1ng_sn@ke_5175d0c8}

[✓] FLAG: picoCTF{N0t_sO_coNfus1ng_sn@ke_5175d0c8}
```

## Key Concepts

### 1. Python Bytecode Architecture

Python uses a **stack-based virtual machine**:
- Operations push/pop values from a stack
- Instructions operate on stack values
- Results are pushed back onto the stack

### 2. XOR Cipher Properties

```python
# XOR is self-inverse
plaintext ^ key = ciphertext
ciphertext ^ key = plaintext

# Example:
'A' (65) ^ 'K' (75) = 10
10 ^ 'K' (75) = 'A' (65)
```

### 3. Common Bytecode Patterns

**Variable Assignment:**
```
LOAD_CONST value
STORE_NAME variable
```

**String Concatenation:**
```
LOAD_NAME str1
LOAD_CONST str2
BINARY_ADD
```

**List Comprehension:**
```
MAKE_FUNCTION
GET_ITER
CALL_FUNCTION
```

### 4. Bytecode Analysis Strategy

1. **Identify data structures** - Look for BUILD_LIST, constants
2. **Track variable flow** - Follow STORE_NAME/LOAD_NAME
3. **Recognize operations** - BINARY_ADD, BINARY_XOR, etc.
4. **Understand control flow** - Loops, conditions
5. **Reconstruct algorithm** - Convert to high-level Python
