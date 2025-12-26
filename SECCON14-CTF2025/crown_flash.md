# SECCON 14 CTF 2025: crown_flash Writeup

**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Techniques:** JIT Deobfuscation, Anti-Debug Traps, GDB Scripting, System Call Tracing

---

## Overview

This challenge involved reverse engineering a heavily obfuscated ELF binary that employed multiple anti-debugging techniques, runtime JIT compilation, and logic traps to protect a flag validation routine.

---

## Phase 1: Black Box Analysis

### 1.1 Binary Identification

```bash
file crown_flash
# Output: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

**Key Properties:**
- **Statically Linked:** All dependencies embedded; `ltrace` ineffective
- **Stripped:** No debug symbols; functions appear as addresses only

### 1.2 System Call Tracing

```bash
strace ./crown_flash
```

**Critical Findings:**

**Integrity Check:**
```c
readlink("/proc/self/exe", "/home/user/crown_flash", 4095) = 51
```
The binary reads its own path and validates the filename. Renaming causes immediate exit.

**Anti-Debugging:**
```c
ptrace(PTRACE_TRACEME) = -1 EPERM (Operation not permitted)
```
Uses `PTRACE_TRACEME` to detect debugger attachment. Since `strace` was already tracing, this call fails by design.

**Timeout Mechanism:**
```c
poll([{fd=0, ...}], 1, 30000)
```
Hard 30-second timeout on input, making manual debugging impractical.

### 💡 Understanding Anti-Debugging (Q&A)

**Q: "The request fails because the 'tracing slot' is already taken. Taken by who?"**

Think of the program as a **Car** and the tracer as the **Driver**. The rule: a car can only have one driver at a time.

- When we ran `strace ./crown_flash`, strace immediately jumped into the driver's seat
- The program then asks the OS: "Can I drive myself?" (`PTRACE_TRACEME`)
- The OS sees strace is already in control and responds: "No. The seat is taken."
- Result: The function returns `-1` (Error)

**Q: "So how do you know there is anti-debug? Strace taking the slot doesn't mean there is anti-debug."**

Think of `strace` as a **court stenographer** - it only writes down what the program says.

- Normal programs like `ls` never call `ptrace` on themselves
- If you see `ptrace(PTRACE_TRACEME)` in the logs, it means the programmer **explicitly wrote code** to ask that question
- **The Mindset:** Normal programs don't check if they're being watched. Paranoid programs do. The act of asking the question is proof of anti-debugging intent.

**Q: "What is strace? When should I use it?"**

- **What:** Records every conversation between the program and the OS kernel (file operations, network, memory allocations)
- **When:** Use it **first** (Phase 1) to get the "big picture" behavior before diving into assembly code

---

## Phase 2: Static Analysis

Opened the binary in Ghidra and located main logic by searching for the string `"Flag: "`.

### 2.1 Input Constraints

**Length Check:**
```c
if (in_stack_00000018 != 0x25) { // 0x25 = 37 decimal
    FUN_002a1a00(..., "Wrong", 5);
    goto LAB_00251d70;
}
```
Input must be exactly **37 characters**.

### 2.2 JIT Code Generation

```c
FUN_0024ee10(&stack0x00000030, uVar4); // Generates code
// ...
iVar1 = (*in_stack_000000c8)(in_stack_00000010, in_stack_00000018, &DAT_0021eda0); // Executes generated code
```

The validation logic is **generated at runtime** as raw machine code, then executed via function pointer. This prevents static analysis of the actual checking algorithm.

### 💡 Understanding Dynamic Code (Q&A)

**Q: "If the address is stored in a variable, it means it was calculated while running... So what?"**

The difference between `function()` and `(*variable)()` is critical:

**Static Analysis (Ghidra)** is like a **printed map** - hardcoded addresses are visible and you can navigate them.

**Dynamic Addresses** `(*variable)` are like the map saying: *"Go to the address written on the Whiteboard in the hallway."*

**So What?** Looking at the map (Ghidra) is useless because the whiteboard is empty until the program runs! You must execute the program (dynamic analysis) to see what gets written.

**Q: "What code hasn't run yet?"**

The **Ghost Code** (JIT code):
- The main program builds a bridge (allocates memory, writes instructions)
- When we break at the call site (`0x00251e44`), the bridge is finished, but we haven't crossed it yet
- We pause at the entrance ramp so we can step onto the bridge manually with `si`

**Q: "Can I just change iVar1 to 1 to print the flag?"**

**No.** This is **hashing**, not decryption:

- **Decryption:** Password → Decrypt → Flag. Patching the check works here.
- **Hashing (This Challenge):** Your Input → Math → Check Result
  - If you input `"AAAA"`, the math gives `5555`. Target is `9999`.
  - Patching the check to say "Correct!" just makes the program lie to you
  - You still don't know the flag - you need to find the input that naturally produces `9999`

---

## Phase 3: Dynamic Analysis

### 3.1 GDB Investigation

```bash
gdb ./crown_flash
break *0x00251e44  # Break at JIT call site
run
# Input: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (37 'A's)
si                 # Step into generated code
x/40i $rip         # Disassemble JIT code
```

### 3.2 Discovered Algorithm

The JIT code implements a custom rolling hash:

- **Initial State:** `EAX = 0x72616e64` ("rand")
- **Per-Character Transform:**
  - XOR input with 4-byte rotating key: `[0x42, 0x19, 0x66, 0x99]`
  - Complex multiplication and bit rotation operations
  - Compare hash against target value

### 3.3 The Logic Trap

```asm
mov    r13d, 0x85e5e637     ; R13 = negative value (sign bit set)
...
test   r13d, 0x80000000     ; Check sign bit
je     skip_corruption      ; Jump if zero (positive)
add    r11d, r15d           ; TRAP: Corrupt hash if negative
skip_corruption:
cmp    r11d, r9d            ; Compare hash vs target
```

**The Mechanism:**
1. `R13` initialized with negative value (MSB = 1)
2. `test` checks if sign bit is set
3. `je` (jump if zero) **fails** because test result is non-zero
4. Execution falls through to `add r11d, r15d`, corrupting the hash
5. Hash will never match target

### 💡 Understanding Assembly Logic (Q&A)

**Q: "What is test? If both same, zero flag will be set as 1?"**

The `test` instruction performs a **Bitwise AND**:
- `1 AND 1 = 1` (Non-Zero)
- `1 AND 0 = 0` (Zero)
- `0 AND 0 = 0` (Zero)

**The Zero Flag (ZF)** works like this:
- If Result is Zero → ZF = 1 (True, "yes it's zero")
- If Result is Non-Zero → ZF = 0 (False, "no it's not zero")

**For our specific case:** `test r13d, 0x80000000`
- Checks the **Sign Bit** (Negative/Positive)
- Negative (`1...`): `1 AND 1 = 1` (Non-Zero) → ZF = 0
- Positive (`0...`): `0 AND 1 = 0` (Zero) → ZF = 1

**Q: "So we have to make A and B same, or not?"**

**No, we want them to be different:**
- A (Mask): `1...` (looking for negative bit)
- B (R13): We want `0...` (positive)
- `1 AND 0 = 0` → This sets the Zero Flag, which unlocks the jump

**Q: "What is the purpose of doing this? (The Trap)"**

Think of it as **The Trampoline Analogy:**

- **The Mud:** The instruction `add r11d, r15d` adds random garbage to your hash
- **The Trampoline:** The instruction `je` (Jump if Zero) lets you fly over the mud

**The Logic:**
- **Default:** R13 is Negative → `test` says "Non-Zero" → Trampoline stays locked → You fall into the mud → Hash Corrupted
- **Our Fix:** We force R13 to Positive → `test` says "Zero" → Trampoline unlocks → You jump over the mud → Hash Clean

**Q: "How can we force R13 to Positive?"**

**Bitwise Masking:** `set $r13 = $r13 & 0x7fffffff`

```
R13 (Negative): 1000...
Mask:           0111... (7 = 0111 in binary)
Operation (&):  The first bit becomes 1 & 0 = 0
                All other bits stay: X & 1 = X
```

This surgically removes the negative sign bit.

---

## Phase 4: Automated Solution

### 4.1 Strategy

1. **Disable Trap:** Set `R13 = R13 & 0x7fffffff` to clear sign bit
2. **Brute Force:** Test each character (ASCII 32-127) against hash targets
3. **State Sync:** Read actual `EAX` register value to maintain synchronization
4. **Keep Alive:** Patch `R11` to match `R9` so binary doesn't exit on wrong guesses

### 4.2 Collision Handling

Initial attempts produced garbage output due to hash collisions at index 2 ('g' vs 'C'). **Fix:** Hardcoded known prefix `SECCON{` to maintain correct internal state.

### 4.3 Final Solver Script

```python
import gdb

# Create dummy input file
with open("flag.txt", "w") as f:
    f.write("A" * 37)

def solve():
    print("[*] Starting Solver...")
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    
    # Break at JIT call site
    gdb.execute("break *0x251e44")
    gdb.execute("run < flag.txt")
    gdb.execute("si")
    
    # Get JIT base address
    try:
        jit_base = int(gdb.parse_and_eval("$rip"))
    except:
        print("[-] Binary exited early.")
        return

    # Disable the trap
    addr_setup = jit_base + 0x13 
    gdb.execute(f"break *{addr_setup}")
    gdb.execute("continue")
    
    print("[!] Patching R13 (Disabling Trap)...")
    gdb.execute("set $r13 = $r13 & 0x7fffffff")
    
    # Setup loop breakpoints
    addr_read  = jit_base + 0x25
    addr_check = jit_base + 0xa5
    
    gdb.execute(f"break *{addr_read}")
    gdb.execute(f"break *{addr_check}")
    gdb.execute("continue")
    
    flag = ""
    XOR_KEY = [0x42, 0x19, 0x66, 0x99]
    KNOWN_PREFIX = "SECCON{"

    # Brute force each character
    for i in range(37):
        try:
            current_eax = int(gdb.parse_and_eval("$eax"))
        except:
            break
        gdb.execute("continue")
        
        try:
            r9 = int(gdb.parse_and_eval("$r9"))
        except:
            break
        target_hash = r9 & 0xFFFFFFFF
        
        found_c = None
        next_eax = 0
        key_byte = XOR_KEY[i % 4]
        
        # Use known prefix to prevent collisions
        if i < len(KNOWN_PREFIX):
            forced_char = KNOWN_PREFIX[i]
            c = ord(forced_char)
            
            # Calculate next state
            r8 = c ^ key_byte
            r9_math = (i * 0x9e3779b9) & 0xFFFFFFFF
            r8 = (r8 + r9_math) & 0xFFFFFFFF
            temp_eax = (current_eax + r8) & 0xFFFFFFFF
            temp_eax = (temp_eax * 0x45d9f3b) & 0xFFFFFFFF
            r10 = (temp_eax << 7) & 0xFFFFFFFF
            r11 = (temp_eax >> 25)
            r10 = r10 | r11
            temp_eax = (temp_eax + r10) & 0xFFFFFFFF
            
            found_c = c
            next_eax = temp_eax
            print(f"[{i}] Forcing known char: '{forced_char}'")
        else:
            # Brute force unknown characters
            for c in range(32, 127):
                r8 = c ^ key_byte
                r9_math = (i * 0x9e3779b9) & 0xFFFFFFFF
                r8 = (r8 + r9_math) & 0xFFFFFFFF
                
                # JIT hashing algorithm
                temp_eax = (current_eax + r8) & 0xFFFFFFFF
                temp_eax = (temp_eax * 0x45d9f3b) & 0xFFFFFFFF
                r10 = (temp_eax << 7) & 0xFFFFFFFF
                r11 = (temp_eax >> 25)
                r10 = r10 | r11
                temp_eax = (temp_eax + r10) & 0xFFFFFFFF
                r11_final = (temp_eax >> 16)
                r11_final = r11_final ^ temp_eax
                
                if r11_final == target_hash:
                    found_c = c
                    next_eax = temp_eax
                    break
        
        if found_c:
            char = chr(found_c)
            flag += char
            if i >= len(KNOWN_PREFIX):
                print(f"[{i}] Found: '{char}'")
            
            # Patch CPU state to keep binary alive
            gdb.execute(f"set $eax = {next_eax}")
            gdb.execute("set $r11 = $r9")
            gdb.execute("continue")
        else:
            print(f"[-] Failed at index {i}")
            break

    print(f"\n[+] FINAL FLAG: {flag}")
    gdb.execute("quit")

solve()
```

---

## Execution

```bash
gdb -q -x solve.py ./crown_flash
```

---

## Result

```
SECCON{good->sPLqsLsooJY,EFwBU8Std7Y}
```

---

## Summary: The Solution Path

1. **Observation:** `strace` revealed the filename check (`readlink`) and anti-debug (`ptrace`)
2. **Dissection:** Ghidra showed the length check (37 chars) and JIT call pointer
3. **Dynamics:** GDB revealed the generated assembly with `test` and `add` instructions
4. **Hypothesis:** The `add` instruction is a trap corrupting the hash, triggered when R13 is negative
5. **Action:** We patched R13 to be positive, disabling the trap
6. **Resolution:** With clean math, we brute-forced the flag character-by-character

---

## Key Takeaways

1. **Multiple Defense Layers:** Combined filename validation, anti-debugging, timeouts, and JIT obfuscation
2. **Runtime Code Generation:** JIT compilation prevents static analysis of core logic
3. **Logic Traps:** Deliberate corruption mechanisms require careful register manipulation
4. **Stateful Attacks:** Character-by-character brute forcing requires maintaining synchronized internal state
5. **GDB Scripting:** Automation essential due to time constraints and complexity
6. **The Hacker Mindset:** Question everything - why does this instruction exist? What's it checking? Understanding the "why" reveals the "how to bypass."
