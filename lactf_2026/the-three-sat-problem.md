# The Three-SAT Problem - LA CTF 2026 Writeup

**Challenge:** The Three-SAT Problem  
**Category:** Reverse Engineering / Cryptography  
**Difficulty:** Hard  
**Flag:** `lactf{is_the_three_body_problem_np_hard}`  

---

## Table of Contents
1. [Challenge Description](#challenge-description)
2. [Initial Reconnaissance](#initial-reconnaissance)
3. [Understanding 3-SAT](#understanding-3-sat)
4. [Static Analysis](#static-analysis)
5. [Deep Dive: The SAT Validator](#deep-dive-the-sat-validator)
6. [Solving Strategy](#solving-strategy)
7. [Symbolic Execution Solution](#symbolic-execution-solution)
8. [Getting the Flag](#getting-the-flag)
9. [Lessons Learned](#lessons-learned)

---

## Challenge Description

We're given a binary `three_sat_problem` with a humorous description about a sci-fi novel where P=NP is proven and cryptography collapses. The challenge is to solve a 3-SAT problem to retrieve the flag.

---

## Initial Reconnaissance

### Basic File Analysis

```bash
$ file three_sat_problem
three_sat_problem: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=2105e69189dfbce45f029e9b3e147b68f0475869,
for GNU/Linux 3.2.0, stripped

$ ls -lh three_sat_problem
-rwxrwxr-x 1 user user 83K Feb  2 07:12 three_sat_problem
```

**Key observations:**
- 64-bit ELF executable
- PIE enabled (Position Independent Executable)
- Stripped (no symbols)
- Small size (83KB)

### Security Features

```bash
$ checksec three_sat_problem
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    PIE enabled
```

**Security posture:**
- ✅ NX enabled (non-executable stack)
- ✅ PIE enabled
- ⚠️ Partial RELRO only
- ❌ No stack canary

### Running the Binary

```bash
$ ./three_sat_problem
Have you solved the Three-Sat Problem?
Please be serious...
```

The binary expects input and validates it. Let's try some basic inputs:

```bash
$ echo "0" | ./three_sat_problem
Have you solved the Three-Sat Problem?
Please be serious...

$ echo "1111111..." | ./three_sat_problem
Have you solved the Three-Sat Problem?
Please be serious...
```

All simple patterns fail validation.

### String Analysis

```bash
$ strings three_sat_problem | grep -E "(flag|lactf|Three)"
Have you solved the Three-Sat Problem?
Please be serious...
I see you haven't.
Incredible! Let me get the flag for you...
```

**Important strings found:**
1. "Have you solved the Three-Sat Problem?" - Initial prompt
2. "Please be serious..." - Validation failure (wrong format)
3. "I see you haven't." - SAT validation failure
4. "Incredible! Let me get the flag for you..." - Success message!

---

## Understanding 3-SAT

Before diving deeper, let's understand what we're dealing with.

**3-SAT (3-Satisfiability)** is a classic NP-complete problem:

- **Input:** Boolean formula in Conjunctive Normal Form (CNF)
- **Format:** Clauses with exactly 3 literals each
- **Goal:** Find variable assignments that satisfy ALL clauses

**Example:**
```
(x₁ ∨ ¬x₂ ∨ x₃) ∧ (¬x₁ ∨ x₂ ∨ ¬x₄) ∧ (x₂ ∨ x₃ ∨ x₄)
```

Each clause (parenthesis) is an OR of 3 literals.
Clauses are connected with AND (∧).
Goal: Assign TRUE/FALSE to variables to make entire formula TRUE.

The challenge joke references P=NP - if proven, 3-SAT could be solved in polynomial time!

---

## Static Analysis

### Disassembly with IDA 

Opening the binary in IDA , we identify key functions:

#### Main Function (0x1090)

```assembly
.text:0000000000001090  push    rbp
.text:0000000000001091  lea     rdi, aHaveYouSolved  ; "Have you solved the Three-Sat Problem?"
.text:0000000000001098  push    rbx
.text:0000000000001099  lea     rbx, dword_15060
.text:00000000000010A0  sub     rsp, 38h
.text:00000000000010A4  call    puts
.text:00000000000010A9  mov     rdi, stdout
.text:00000000000010B0  call    fflush
.text:00000000000010B5  mov     rdx, stdin
.text:00000000000010BC  mov     esi, 500h        ; Read 0x500 (1280) bytes
.text:00000000000010C1  mov     rdi, rbx
.text:00000000000010C4  call    fgets
```

**Analysis:**
1. Prints the prompt message
2. Reads up to **1280 bytes** into buffer at `0x15060`
3. Uses `fgets()` for input

#### Input Validation

```assembly
.text:00000000000010C9  mov     rdi, rbx
.text:00000000000010CC  lea     rsi, aNewline       ; "\n"
.text:00000000000010D3  call    strcspn
.text:00000000000010D8  mov     rdi, rbx
.text:00000000000010DB  mov     byte ptr [rbx+rax], 0  ; Remove newline
.text:00000000000010DF  call    strlen
.text:00000000000010E4  cmp     rax, 4FFh        ; Check length == 0x4FF (1279)
.text:00000000000010EA  je      validation_ok
.text:00000000000010EC  lea     rdi, aPleaseBeSerio  ; "Please be serious..."
.text:00000000000010F3  jmp     print_and_exit
```

**Key constraint:** Input must be exactly **1279 characters** long!

#### Character Validation Loop

```assembly
.text:00000000000010F5  lea     rdx, [rbx+4FFh]   ; End pointer
.text:00000000000010FC  mov     rbp, rbx
.text:00000000000010FF loop_start:
.text:00000000000010FF  mov     al, [rbx]
.text:0000000000001101  sub     eax, 30h          ; Subtract '0' (ASCII 48)
.text:0000000000001104  cmp     al, 1
.text:0000000000001106  ja      invalid_char      ; If > 1, invalid
.text:0000000000001108  inc     rbx
.text:000000000000110B  cmp     rdx, rbx
.text:000000000000110E  jne     loop_start
```

**Analysis:**
- Each character must be '0' (0x30) or '1' (0x31)
- Subtracting 0x30 gives 0 or 1
- Checking if result > 1 validates the character

#### The SAT Validator Call

```assembly
.text:0000000000001110  xor     eax, eax
.text:0000000000001112  call    sub_1289          ; THE SAT VALIDATOR!
.text:0000000000001117  test    al, al            ; Check return value
.text:0000000000001119  je      validation_failed
```

This calls the SAT validation function at `0x1289`.

#### Special Check: The Mystery Byte

```assembly
.text:000000000000111B  test    byte ptr [rip+14230h], 1  ; Address: 0x15352
.text:0000000000001122  jne     success
.text:0000000000001124  lea     rdi, aISeeYouHavent  ; "I see you haven't."
.text:000000000000112B  call    puts
```

**Critical discovery:**
- After SAT validation passes, there's an additional check
- Tests bit 0 of byte at address `0x15352`
- Calculating the offset: `0x15352 - 0x15060 = 0x2F2 = 754`
- **Input bit 754 must be '1'!**

#### Flag Extraction Logic

```assembly
.text:0000000000001135  lea     rdi, aIncredibleLet  ; "Incredible! Let me get the flag for you..."
.text:000000000000113C  call    puts
.text:0000000000001141  xorps   xmm0, xmm0
.text:0000000000001144  lea     rdi, [rsp+17h]
.text:0000000000001149  xor     eax, eax
.text:000000000000114B  movups  [rsp+7], xmm0     ; Clear 16 bytes
.text:0000000000001150  push    19h
.text:0000000000001152  pop     rcx
.text:0000000000001153  rep stosb                  ; Clear 25 bytes
.text:0000000000001155  xor     eax, eax
.text:0000000000001157  lea     rdi, dword_13080   ; Array of indices!
```

**The extraction loop:**

```assembly
.text:000000000000115E loop_extract:
.text:000000000000115E  movsxd  rdx, dword [rdi+rax*4]  ; Get index from array
.text:0000000000001162  mov     esi, eax
.text:0000000000001164  mov     ecx, eax
.text:0000000000001166  inc     rax
.text:0000000000001169  sar     esi, 3              ; Divide by 8 (byte index)
.text:000000000000116C  and     ecx, 7              ; Modulo 8 (bit index)
.text:000000000000116F  mov     dl, [rbp+rdx]       ; Get input bit
.text:0000000000001173  movsxd  rsi, esi
.text:0000000000001176  and     edx, 1              ; Isolate bit
.text:0000000000001179  shl     edx, cl             ; Shift to position
.text:000000000000117B  or      [rsp+rsi+7], dl     ; OR into output buffer
.text:000000000000117F  cmp     rax, 140h           ; Loop 320 times (0x140)
.text:0000000000001185  jne     loop_extract
```

**Flag extraction algorithm:**
```python
for i in range(320):
    index = dword_13080[i]      # Get bit index from array
    bit = input[index] & 1      # Extract bit from input
    output[i//8] |= bit << (i%8)  # Pack into output byte
```

The flag is constructed from **320 specific bits** of the 1279-bit input!

### Extracting the Bit Indices

Let's dump the `dword_13080` array:

```bash
$ objdump -s -j .rodata three_sat_problem | grep -A 50 "13080"
```

Or using Python:

```python
import struct

with open('three_sat_problem', 'rb') as f:
    f.seek(0x13080)
    indices = struct.unpack('<320I', f.read(1280))

print(f"Flag bit indices: {indices}")
# [295, 987, 120, 287, 395, 844, 655, 196, ...]
```

**Summary:** 320 DWORDs at `0x13080` specify which input bits form the flag.

---

## Deep Dive: The SAT Validator

The SAT validator function `sub_1289` is **massive** - let's analyze it.

### Function Size

```bash
$ objdump -d three_sat_problem | grep -A 1 "^0000000000001289"
0000000000001289 <.text+0x1289>:
    1289: 41 57                 push   %r15
    ...
    (13,805 lines of assembly!)
    ...
    2981: c3                    ret
```

**Statistics:**
- **13,805 lines** of assembly
- **960 bytes** stack allocation (`sub rsp, 0x3C0`)
- Uses registers: rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r15

### Exporting for Analysis

In IDA Pro, we can export this function:
1. Navigate to address `0x1289`
2. Right-click → "Copy to assembly" or use IDA's export feature
3. Save as `sub_1289.txt`

### Pattern Analysis

Analyzing the assembly reveals three phases:

#### Phase 1: Variable Setup (Lines 1-8000)

```assembly
mov     al, byte ptr cs:dword_15060
not     eax
and     eax, 1
mov     byte ptr [rsp+3F0h+var_460+1], al
```

**Pattern:**
1. Load byte from input buffer (addresses 0x15060-0x1555E)
2. NOT the value (create negated literal)
3. Store on stack

This creates **positive and negative literals** for SAT variables.

#### Phase 2: Clause Evaluation (Lines 8000-13000)

```assembly
mov     al, [rsp+X]
or      al, byte ptr cs:dword_YYYY
or      al, [rsp+Z]
and     eax, edx
```

**Pattern:**
- Multiple OR operations combine literals in a clause
- AND operations combine clauses together
- Progressive accumulation in registers

#### Phase 3: Final Result

```assembly
and     eax, edx
and     eax, ecx
; ... more ANDs ...
ret
```

Final result returned in **EAX register** (AL specifically).

### Counting Operations

```bash
$ grep -c " or " sub_1289.txt
3411

$ grep -c " and " sub_1289.txt
3661

$ grep -c " not " sub_1289.txt
1466
```

**This is a HUGE CNF formula:**
- ~3,400 OR operations (building clauses)
- ~3,600 AND operations (combining clauses)
- ~1,500 NOT operations (negated literals)

---

## Solving Strategy

Given the complexity, we have several approaches:

### Approach 1: Manual Clause Extraction ❌
- Parse 13,805 lines of assembly
- Identify each clause
- Build CNF formula
- Solve with SAT solver

**Problem:** Too error-prone and time-consuming.

### Approach 2: Angr Symbolic Execution ❌
- Use angr to symbolically execute the binary
- Let it extract constraints automatically

**Problem:** Binary is too complex, angr struggles with PIE and the massive function.

### Approach 3: Symbolic Execution on Assembly ✅
- Parse the exported assembly line-by-line
- Simulate each instruction with Z3 (SMT solver)
- Build symbolic expressions
- Solve with Z3

**This is our chosen approach!**

---

## Symbolic Execution Solution

### The Strategy

Instead of trying to understand the SAT formula, we'll **simulate the assembly** symbolically:

1. Create 1279 Z3 Boolean variables (one per input bit)
2. Parse each assembly instruction
3. Track state (registers, stack, memory)
4. Simulate each operation (mov, not, and, or, xor)
5. Add constraint: final result (EAX) == True
6. Add constraint: input[754] == True (from main check)
7. Solve with Z3
8. Extract solution

### Implementation

```python
#!/usr/bin/env python3
import re
from z3 import *

def solve():
    s = Solver()

    # Create 1279 boolean variables for input
    input_vars = [Bool(f'input_{i}') for i in range(1279)]

    # State tracking
    stack = {}   # Maps stack offsets to Z3 expressions
    regs = {}    # Maps registers to Z3 expressions

    def parse_address(addr_str):
        """Parse address like 'dword_15060+2' to input index"""
        clean = addr_str.replace("cs:", "")
        clean = clean.replace("byte ptr ", "")
        clean = clean.replace("dword ptr ", "").strip()

        match = re.search(r'(?:dword|byte)_([0-9A-Fa-f]+)', clean)
        if not match:
            return None

        base_addr = int(match.group(1), 16)
        offset = 0
        if '+' in clean:
            try:
                offset = int(clean.split('+')[-1])
            except:
                pass

        index = (base_addr + offset) - 0x15060
        if 0 <= index < 1279:
            return index
        return None

    def normalize_reg(reg):
        """Normalize register names: al,eax,rax -> 'a'"""
        reg = reg.lower().strip()

        # Handle r8-r15
        if reg.startswith('r') and len(reg) > 1 and reg[1].isdigit():
            return re.sub(r'[bdwl]$', '', reg)

        # Standard registers
        if 'a' in reg: return 'a'
        if 'b' in reg and 'bp' not in reg: return 'b'
        if 'c' in reg: return 'c'
        if 'd' in reg and 'di' not in reg: return 'd'
        if 'si' in reg: return 'si'
        if 'di' in reg: return 'di'
        return reg

    def get_value(operand):
        """Get Z3 expression for operand"""
        operand = operand.strip()

        # Immediate value
        if operand.isdigit():
            return operand == '1'

        # Stack reference
        if '[rsp' in operand or '[RSP' in operand:
            inner = re.sub(r'byte ptr |dword ptr |\[|\]', '', operand)
            return stack.get(inner, BoolVal(False))

        # Memory reference (input variable)
        if 'dword_' in operand or 'byte_' in operand or 'cs:' in operand:
            idx = parse_address(operand)
            if idx is not None:
                return input_vars[idx]
            return BoolVal(False)

        # Register
        reg_key = normalize_reg(operand)
        return regs.get(reg_key, BoolVal(False))

    def set_value(operand, value):
        """Set operand to Z3 expression"""
        operand = operand.strip()

        if '[rsp' in operand or '[RSP' in operand:
            inner = re.sub(r'byte ptr |dword ptr |\[|\]', '', operand)
            stack[inner] = value
        else:
            reg_key = normalize_reg(operand)
            regs[reg_key] = value

    # Parse assembly file
    print("[*] Parsing assembly (13,805 lines)...")
    with open("sub_1289.txt", "r") as f:
        lines = f.readlines()

    instruction_count = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith(';'):
            continue

        # Extract opcode and operands
        parts = line.split()
        opcode = None
        operands_start = -1

        for i, part in enumerate(parts):
            if part in ['mov', 'not', 'and', 'or', 'xor']:
                opcode = part
                operands_start = i + 1
                break

        if not opcode or operands_start >= len(parts):
            continue

        operands_str = ' '.join(parts[operands_start:])
        operands = [op.strip() for op in operands_str.split(',')]

        # Simulate instruction
        if opcode == 'mov' and len(operands) >= 2:
            set_value(operands[0], get_value(operands[1]))
            instruction_count += 1

        elif opcode == 'not' and len(operands) >= 1:
            set_value(operands[0], Not(get_value(operands[0])))
            instruction_count += 1

        elif opcode == 'and' and len(operands) >= 2:
            if operands[1].strip() != '1':
                val1 = get_value(operands[0])
                val2 = get_value(operands[1])
                set_value(operands[0], And(val1, val2))
                instruction_count += 1

        elif opcode == 'or' and len(operands) >= 2:
            val1 = get_value(operands[0])
            val2 = get_value(operands[1])
            set_value(operands[0], Or(val1, val2))
            instruction_count += 1

        elif opcode == 'xor' and len(operands) >= 2:
            val1 = get_value(operands[0])
            if operands[1].strip() == '1':
                set_value(operands[0], Not(val1))
            else:
                val2 = get_value(operands[1])
                set_value(operands[0], Xor(val1, val2))
            instruction_count += 1

    print(f"[+] Processed {instruction_count} instructions")

    # Add constraints
    print("[*] Adding constraints:")
    print("    1. EAX == True (SAT must be satisfied)")
    print("    2. input[754] == True (required by main)")

    final_result = regs.get('a')  # EAX
    if final_result is None:
        print("[-] Error: EAX not found!")
        return None

    s.add(final_result == True)
    s.add(input_vars[754] == True)

    # Solve
    print("[*] Solving with Z3 (this may take 30-60 seconds)...")
    if s.check() == sat:
        print("[+] SAT! Solution found!")

        m = s.model()
        solution = ''
        for i in range(1279):
            val = m.evaluate(input_vars[i], model_completion=True)
            solution += '1' if is_true(val) else '0'

        print(f"[+] Solution: {solution[:80]}...")
        print(f"[+] Ones: {solution.count('1')}")
        print(f"[+] Bit 754: {solution[754]}")

        # Save solution
        with open('solution.txt', 'w') as f:
            f.write(solution)

        return solution
    else:
        print("[-] UNSAT")
        return None

if __name__ == '__main__':
    solution = solve()

    if solution:
        print("\n[*] Testing on binary...")
        import subprocess
        result = subprocess.run(
            ['./three_sat_problem'],
            input=solution.encode(),
            capture_output=True,
            timeout=5
        )

        output = (result.stdout + result.stderr).decode()
        print(output)

        if 'lactf{' in output:
            print("\n🎉 FLAG CAPTURED! 🎉")
```

### Running the Solver

```bash
$ python3 solver.py
[*] Parsing assembly (13,805 lines)...
[+] Processed 13423 instructions
[*] Adding constraints:
    1. EAX == True (SAT must be satisfied)
    2. input[754] == True (required by main)
[*] Solving with Z3 (this may take 30-60 seconds)...
[+] SAT! Solution found!
[+] Solution: 0101100110...
[+] Ones: 647
[+] Bit 754: 1

[*] Testing on binary...
Have you solved the Three-Sat Problem?
Incredible! Let me get the flag for you...
lactf{is_the_three_body_problem_np_hard}

🎉 FLAG CAPTURED! 🎉
```

---

## Getting the Flag

The solution works! Let's understand what happened:

### The Solution

```
1279-bit binary string with:
- Exactly 647 ones
- Bit 754 = 1
- Satisfies the 3-SAT formula
```

### Flag Extraction

The binary takes our solution and:
1. Validates it passes the SAT check (sub_1289 returns True)
2. Checks bit 754 == 1
3. Extracts 320 bits using indices from dword_13080
4. Packs them into 40 bytes
5. Prints as ASCII: `lactf{is_the_three_body_problem_np_hard}`

### The Three-Body Problem Reference

The flag references the **Three-Body Problem** from physics:
- Famous problem in celestial mechanics
- No general analytical solution exists
- The challenge asks: "Is it NP-hard?"
- A clever nod to computational complexity theory!

---

## Lessons Learned

### Key Takeaways

1. **Don't overthink complexity**: When faced with 13K lines of assembly, symbolic execution can be simpler than manual analysis.

2. **Multiple validation layers**: The challenge had:
   - Format validation (1279 chars of '0'/'1')
   - SAT validation (sub_1289)
   - Special bit check (bit 754)
   - All must pass!

3. **Flag extraction != Direct decoding**: The flag wasn't the SAT solution itself, but extracted from specific bit positions.

4. **Z3 is powerful**: SMT solvers like Z3 can solve complex constraints that would be intractable manually.

5. **Export and analyze**: When reversing is hard, export the code and analyze it programmatically.

### Common Pitfalls

**❌ Mistake 1:** Trying to manually extract all 3,600+ clauses
**✅ Solution:** Use symbolic execution instead

**❌ Mistake 2:** Forgetting the bit 754 constraint
**✅ Solution:** Complete static analysis before solving

**❌ Mistake 3:** Trying to decode the solution directly
**✅ Solution:** Feed it to the binary and let it extract the flag

### Tools Used

- **IDA Pro**: Static analysis and assembly export
- **Python 3**: Scripting the solver
- **Z3 Solver**: SMT solving
- **pwndbg**: Dynamic analysis (optional)
- **objdump**: Binary inspection

---

## Alternative Approaches

### Method 1: Manual Clause Extraction

Extract clauses from assembly and feed to specialized SAT solvers:

```bash
# After extracting CNF to DIMACS format
$ minisat problem.cnf solution.txt
$ glucose problem.cnf solution.txt
```

**Pros:** Industrial SAT solvers are very fast
**Cons:** Extracting clauses correctly is error-prone

### Method 2: Angr Symbolic Execution

```python
import angr
import claripy

proj = angr.Project('./three_sat_problem')
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x1135, avoid=[0x1124, 0x112b])
```

**Pros:** Automatic constraint extraction
**Cons:** May timeout on complex binaries

### Method 3: Dynamic Analysis with Constraint Logging

Use pwndbg to trace execution and log which clauses fail:

```gdb
(gdb) break *0x1289
(gdb) run < test_input.txt
(gdb) # Trace through and log constraints
```

**Pros:** Ground truth from actual execution
**Cons:** Very time-consuming

---

## Appendix: Commands Reference

### Setting Up Environment

```bash
# Install Z3
pip install z3-solver

# Verify installation
python3 -c "from z3 import *; print(Solver().check())"
```

### Analysis Commands

```bash
# Basic reconnaissance
file three_sat_problem
checksec three_sat_problem
strings three_sat_problem
objdump -d three_sat_problem > disasm.txt

# Extract data sections
objdump -s -j .rodata three_sat_problem

# Run the binary
./three_sat_problem
echo "test" | ./three_sat_problem

# Debugging
gdb ./three_sat_problem
pwndbg> break main
pwndbg> run
```

### Solver Execution

```bash
# Run the symbolic execution solver
python3 solver.py

# Test the solution
cat solution.txt | ./three_sat_problem
```

---

## Conclusion

This challenge brilliantly combined:
- Reverse engineering
- Boolean satisfiability (3-SAT)
- Symbolic execution
- Computational complexity theory

The key insight was recognizing that symbolic execution on the exported assembly was more tractable than trying to understand the SAT formula directly. By simulating the assembly with Z3, we let the SMT solver do the heavy lifting.

**Final flag:** `lactf{is_the_three_body_problem_np_hard}`

---
