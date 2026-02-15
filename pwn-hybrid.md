## HYBRID WORKFLOW (Human + AI with Claude Code)

**How to use this:** First, input this entire methodology file as context. Then use the phase prompts below one at a time. Read and understand each AI response before proceeding to the next phase. You are the brain; AI is your tool.

---

### PROMPT 1 — RECON (copy-paste this)

```
PHASE 0: RECON ONLY. Do NOT analyze source code or decompile functions yet.

Do these steps and report findings:

1. List all provided files (ls -la, file *)
2. Run checksec on the binary
3. If Dockerfile exists: extract libc and ld-linux, then run pwninit to patch
4. If libc provided: get version (strings libc.so.6 | grep "GNU C Library"), run one_gadget
5. Run the binary with sample inputs — what does it do? What's the UI/menu?
6. Quick checks:
   - Any win/flag/shell functions? (objdump -t | grep -iE "win|flag|shell|secret")
   - system@plt or execve? (objdump -d | grep -E "system|execve")
   - "/bin/sh" string? (strings | grep "/bin/sh")
   - Useful gadgets? (ROPgadget --binary | grep "pop rdi")
7. readelf -S binary — list all sections with addresses and permissions
   (especially .bss, .data, .got.plt sizes and offsets)
8. readelf -l ./binary — list all segments with addresses and permissions

Report format:
- Binary type + architecture
- ALL protections (PIE/Canary/NX/RELRO) with implications
- Libc version if available
- Quick win possibilities (if any)
- Section Map: .text, .plt, .got, .data, .bss addresses + sizes
- What the program appears to do (from running it)
- Remote connection info
```

**After AI reports back:** Read it. Understand the binary's protections and basic behavior. If there's a quick win (win function, no PIE + no canary), tell AI to try it immediately. Otherwise proceed to Prompt 2.

---

### PROMPT 2 — DEEP ANALYSIS (copy-paste this)

```
PHASE 1: DEEP STATIC + DYNAMIC ANALYSIS. This is the most critical phase.

Use Ghidra MCP and pwndbg MCP. Your analysis must cover:

A. PROGRAM UNDERSTANDING (explain like I'm reading the source)
   1. What does main() do? Full control flow.
   2. For EVERY function called from main: what does it do? What are its parameters?
   3. What data structures exist? (arrays, structs, linked lists — draw them)
   4. How does user input flow through the program? (where stored, how processed)
   5. What's the intended/normal behavior?

B. VULNERABILITY HUNT (find ALL bugs, not just the obvious one)
   For each vulnerability found:
   - WHERE: exact function + offset
   - WHAT: what type of bug (overflow, UAF, format string, etc.)
   - WHY: why does this bug exist (off-by-one? missing check? wrong size?)
   - PRIMITIVE: what can an attacker DO with this bug?
     → Can I read? What? How much?
     → Can I write? Where? How much? How many times?
     → Can I control execution? (RIP/function pointers)

C. MEMORY LAYOUT (use GDB to verify, don't guess)
   1. Draw the stack frame of the vulnerable function with GDB:
      - Run: b vulnerable_func, r, info frame, x/40gx $rsp
      - Show: every variable, its offset from RSP/RBP, its size
      - HIGHLIGHT: what's adjacent to our input (loop counters? sizes? pointers?)
   2. If heap challenge: show chunk layout, tcache state, bin state
   3. Map ALL writable regions I can potentially target:
      - .bss address + what's there (is it zero? how much space?)
      - .got addresses (writable if Partial RELRO)
      - Any global pointers or buffers

D. CONSTRAINTS ANALYSIS
   - What limits do I have? (buffer size, number of operations, filters)
   - What does each constraint SUGGEST about the intended approach?
   - What's NOT restricted that I can use?

Report to me:
1. Challenge overview (what it does, how to interact)
2. Each function explained clearly
3. ALL vulnerabilities found with primitives
4. Stack/heap layout diagram (from GDB)
5. Writable memory map
6. Your initial theory on the exploit path
7. Any questions or uncertainties you have
```

**After AI reports back:** This is where YOU think critically. Ask yourself:
- Does the exploit theory make sense?
- Did AI consider ALL memory regions, or only the obvious target?
- Are there variables adjacent to the buffer that AI ignored?
- Did AI miss any bugs?
- Does the constraint analysis reveal the author's intent?

If anything seems off or incomplete, ask follow-up questions before proceeding.

---

### PROMPT 3 — EXPLOIT STRATEGY (copy-paste this)

```
PHASE 2: EXPLOIT STRATEGY. Do NOT write code yet. Plan the full attack.

Based on your analysis, answer these questions:

1. DIFFICULTY: Is this Easy (standard technique), Medium (needs leak), or Hard (needs creativity)?

2. IF EASY/MEDIUM: What's the standard approach?
   - Propose the simplest working attack
   - Explain each step of the chain

3. IF HARD: Run the offensive reasoning checklist:
   A. What else is on the stack/heap NEAR our overflow? (counters, sizes, pointers, booleans)
   B. What writable memory can I use to store payloads? (.bss, .data, heap)
   C. Can I corrupt WHERE the program reads/writes? (redirect pointers)
   D. What side effects do library functions have? (printf→malloc, exit→flush)
   E. Can I abuse internal metadata? (tcache counts, FILE structs, GOT)
   F. Any signed/unsigned or type confusion?
   G. What does the challenge author WANT me to do? (what do the constraints suggest?)

4. FULL CHAIN (plan every stage):
   Phase 1: [action] → [result we get]
   Phase 2: [action using result] → [next result]
   ...
   Final: [trigger] → shell/flag

   STATE: After each phase what addresses/values do we know?

5. SANITY CHECK:
   - Does each step depend only on things we already have?
   - Is there a simpler way to achieve the same result?
   - What could go wrong at each step?

Present the strategy. I will review and approve before you code.
```

**After AI reports back:** This is the critical review point.
- Does the chain make logical sense step-by-step?
- Is AI trying a standard technique that clearly won't work here?
- Has it considered the creative options (A-G)?
- If you disagree or have an idea, tell AI now.

---

### PROMPT 4 — EXPLOIT (copy-paste this)

```
PHASE 3: IMPLEMENT THE EXPLOIT. Build incrementally with checkpoints.

Rules:
1. Write one phase at a time. After each phase, verify it works before proceeding.
2. After each phase, print the obtained value with log.success() and verify:
   - Is the leaked address aligned? (heap = 0x5X, libc = 0x7f, stack = 0x7ff)
   - Does it match expected ranges?
3. Use GDB (pwndbg MCP) to verify memory state after each phase.
4. If ANY checkpoint fails: STOP. Show me the GDB output. Do NOT proceed blindly.

Start with Phase 1 of our strategy. Show me the result before continuing.
```

**After AI reports Phase 1 works:** Tell it to proceed phase by phase:
```
Phase 1 looks good. Proceed to Phase 2.
```

**If something fails:**
```
That didn't work. Use GDB to examine:
1. What's actually on the stack/heap at the crash point? (x/40gx $rsp)
2. What does the crash register state look like? (info registers)
3. Does the memory layout match what we expected?
Show me the GDB output before trying a fix.
```

---

### PROMPT 5 — WHEN STUCK (use when needed)

```
STOP. The current approach isn't working. Let's reassess.

1. Show me exactly WHERE it fails (GDB backtrace + register state + stack dump)
2. Show me WHAT we expected vs WHAT actually happened
3. Don't try another variation of the same approach. Instead:

   Ask yourself:
   - Am I targeting the right memory location?
   - Am I missing a different vulnerability I didn't consider?
   - Is there a variable/pointer adjacent to my buffer I could corrupt instead?
   - Am I wrong about the memory layout? (verify with GDB, don't guess)
   - Could a completely different approach work?
     * Write shellcode to .bss instead?
     * Use a different function in the binary as a gadget?
     * Corrupt a different metadata structure?
     * Use a side-effect of a library function?

   Think about what the challenge AUTHOR intended. What technique does
   the combination of protections + vulnerability + constraints point to?

Present 2-3 alternative approaches ranked by likelihood.
```

---

### TIPS FOR THE HYBRID WORKFLOW

```
DO:
✓ Read and UNDERSTAND each AI response before proceeding
✓ Ask "did you check what's adjacent to the buffer?" after analysis
✓ Ask "what writable memory regions exist?" if AI only targets return addr
✓ Challenge AI's approach: "why not X instead?"
✓ Give AI YOUR ideas: "I think we should write to .bss because..."
✓ Use Prompt 5 early if you feel AI is going in circles

DON'T:
✗ Skip the analysis phase — this is where the exploit is born
✗ Let AI try 10 variations of a failing approach
✗ Accept "this should work" without seeing GDB proof
✗ Proceed to next phase without verifying current phase works
✗ Let AI overcomplicate an easy challenge
✗ Let AI oversimplify a hard challenge
```
