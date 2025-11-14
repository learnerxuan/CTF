# PWN Challenge Quick Reference - Critical Questions

**Use this checklist AFTER basic analysis (checksec, offset, etc.)**

---

## 🎯 Before Writing Exploit

### 1. **Dockerfile Check (FIRST THING!)**
```
[ ] Is Dockerfile provided?
    → YES: Extract libc IMMEDIATELY
    → NO: Need to identify libc via leaks

Command: docker cp container:/srv/lib/i386-linux-gnu/libc-*.so ./
```

### 2. **Program Flow Analysis**
```
[ ] Where does the vulnerable function get called from?
[ ] What happens AFTER the vulnerable function returns?
[ ] Does the program have validation/checks that run multiple times?
[ ] If I return to X, what's the stack state?
```

**Key Question:** *"What does the program naturally do after this function?"*

---

## 🔄 Choosing Return Address

### Decision Tree:

```
After exploitation, where should I return?

Option A: Vulnerable function (0x8048772)
├─ ✗ Stack is corrupted from ROP chain
├─ ✗ No validation checks (broken flow)
└─ ✗ Unpredictable when it tries to return again

Option B: Main function (0x80487A1)
├─ ✓ Resets and realigns stack
├─ ✓ Runs validation naturally
├─ ✓ Clean state for next stage
└─ ✓ Reliable execution

Option C: Exit function
└─ Only if you don't need second stage
```

**Key Questions:**
- *"Will I need to send another payload?"* → Return to main/start
- *"Does returning here reset the stack?"* → Check function prologue
- *"What's the natural program flow?"* → Follow that

---

## 🧹 Stack Cleanup

### When You Need pop Gadget:

```
32-bit with N arguments → Need N pops (or add esp, N*4)
64-bit → Usually NO cleanup needed

Quick Test:
[ ] Am I chaining multiple ROP gadgets?
    → YES: Need cleanup between each
[ ] Am I returning to main/function that resets stack?
    → NO: Need cleanup
    → YES: Maybe not needed (main resets it)
```

**Mental Model:**
```
Without cleanup:
[func1][func2][arg1]
       ^ After func1, ESP points at arg1 (WRONG!)

With cleanup:
[func1][pop;ret][arg1][func2]
       ^ After func1, pop removes arg1, ESP at func2 (RIGHT!)
```

---

## 📍 Return Address Selection Strategy

### Ask These Questions:

1. **"Does this function reset ESP?"**
   ```asm
   Check for:
   and esp, 0xfffffff0    ; Stack alignment
   sub esp, 0x??          ; New frame allocation
   ```
   → If YES: Safe to return here without cleanup

2. **"Will I need program state again?"**
   - Need validation? → Return to main
   - Need input again? → Return to main
   - One-shot exploit? → Can return anywhere/exit

3. **"What's on the stack when I return here?"**
   - Garbage from ROP? → Need cleanup or reset
   - Clean state? → Safe to proceed

---

## 🔍 Common Pitfalls Checklist

### Before Running Exploit:

```
[ ] Did I extract libc from Docker? (If Dockerfile exists)
[ ] Did I verify libc offsets with multiple leaks?
[ ] Did I test locally first?
[ ] Did I check if validation happens more than once?
[ ] Did I consider stack alignment?
[ ] Did I add cleanup gadgets between ROP calls?
```

### If Exploit Fails:

```
[ ] Is libc version correct? (leak 2+ functions to verify)
[ ] Is return address correct? (should reset stack or lead to clean state)
[ ] Is stack aligned? (especially for 64-bit)
[ ] Did I pass all validation checks?
[ ] Did I account for all function arguments?
```

---

## 💡 Key Insights

### Return to Main vs Vuln:

| Aspect | Vuln Function | Main Function |
|--------|--------------|---------------|
| Stack State | Corrupted | Clean/Reset |
| Validation | Skipped | Runs Again |
| Reliability | Unstable | Stable |
| Use When | One-shot | Multi-stage |

### The Golden Rule:

**"Return to where the program naturally expects to be, not where it's convenient for you"**

If the program flow is:
```
main() → validation() → vuln() → return to main → exit
```

Your exploit should follow the SAME flow:
```
exploit stage 1 → return to main → validation → exploit stage 2
```

---

## 🎓 Advanced Considerations

### Multi-Stage Attacks:

```
Stage 1: Leak
├─ Return to: main (for stage 2)
├─ Why: Need program to run again
└─ Stack: Will be reset by main

Stage 2: Exploit  
├─ Return to: anywhere/exit
├─ Why: Final payload, no need to continue
└─ Stack: Doesn't matter
```

### 64-bit Differences:

```
32-bit:
- Args on stack → Need pop for cleanup
- call pushes return address on stack

64-bit:
- Args in registers (rdi, rsi, rdx, rcx, r8, r9)
- No cleanup needed for register args
- Stack needs 16-byte alignment (and rsp, -0x10)
```

---

## 📋 Quick Decision Matrix

### "Should I return to main?"

```
┌─────────────────────────────────┬─────────────┐
│ Scenario                        │ Return to   │
├─────────────────────────────────┼─────────────┤
│ Need to send payload again      │ main        │
│ Program has validation          │ main        │
│ Multi-stage attack              │ main        │
│ Stack is corrupted              │ main        │
│ One-shot exploit                │ exit/system │
│ Have clean libc base already    │ anywhere    │
└─────────────────────────────────┴─────────────┘
```

### "Do I need cleanup gadget?"

```
┌─────────────────────────────────┬──────────┐
│ Scenario                        │ Cleanup? │
├─────────────────────────────────┼──────────┤
│ 32-bit, calling function        │ YES      │
│ 64-bit, calling function        │ NO       │
│ Returning to main               │ MAYBE    │
│ Chaining multiple gadgets       │ YES      │
│ Last gadget in chain            │ NO       │
└─────────────────────────────────┴──────────┘
```

---

## 🔧 Debugging Approach

When exploit doesn't work:

1. **Test each stage separately**
   ```python
   # Stage 1 only
   io.sendline(payload1)
   leak = u32(io.recv(4))
   print(f"Leak: {hex(leak)}")
   exit()  # Stop here to verify leak works
   ```

2. **Verify return address**
   ```python
   # Add logging
   log.info(f"Returning to: {hex(return_addr)}")
   # Check if program asks for validation again
   try:
       io.recvuntil(b"Where are you", timeout=2)
       log.success("Returned to main successfully!")
   except:
       log.error("Did not return to expected location")
   ```

3. **Check stack alignment**
   ```bash
   # In gdb, after overflow:
   x/20wx $esp  # See what's on stack
   ```

---

## Summary: The 3 Critical Questions

Before finalizing your exploit, ask:

1. **"Did I extract the CORRECT libc?"** (from Docker if provided)
2. **"Where should I return to keep the program alive?"** (usually main)
3. **"Is the stack clean for the next stage?"** (use cleanup gadgets if needed)

**Remember:** Follow the natural program flow, don't fight against it!
