## HYBRID WORKFLOW (Human + AI with Claude Code)

**How to use this:** First, input this entire methodology file as context. Then use the phase prompts below one at a time. Read and understand each AI response before proceeding to the next phase. You are the brain; AI is your tool.

---

### TOKEN DISCIPLINE (read this before every session)

These rules apply to EVERY phase. Breaking them causes debugging spirals that waste tokens.

```
HARD RULES:

1. GHIDRA-FIRST POLICY
   - Exhaust ALL static analysis (Ghidra MCP) before touching pwndbg
   - Every question you CAN answer from decompilation, answer there — zero runtime cost
   - Only open pwndbg to VERIFY a specific hypothesis, never to "explore"

2. NO GDB SCRIPTS — EVER
   - NEVER write separate Python GDB scripts (gdb_debug.py, exploit_debug.py, etc.)
   - Each script costs tokens to write + run + parse output + usually asks the wrong question
   - Use pwndbg MCP directly: one breakpoint → one register/address → one answer → stop
   - Real example: 3 GDB scripts failed to find a wrong offset. 5 pwndbg MCP calls found it.

3. PWNDBG IS A CALCULATOR, NOT A LOGGING SYSTEM
   - You give it a specific address → it gives you one number
   - You give it a breakpoint → it stops at one instruction
   - You read one register → you update or kill your hypothesis
   - Then you STOP the debug session
   - NEVER: "let me run it and see what happens"
   - NEVER: dump 200 lines of heap/memory output "just in case"

4. HYPOTHESIS-DRIVEN DEBUGGING
   Before opening pwndbg, answer these three questions:
   [ ] Can I state my hypothesis in one sentence?
   [ ] Do I know exactly which instruction to break at?
   [ ] Do I know exactly which register/address to read?
   If you can't answer all three → you're not ready to debug. Go back to Ghidra.

5. 3-STRIKE RULE
   - After 3 failed attempts at the SAME approach → MANDATORY STOP
   - Do NOT try variation #4. The approach is wrong.
   - Go back to static analysis and re-examine your assumptions

6. WRITEUP/RESOURCE PROTOCOL
   When writeups, hints, or reference material are provided:
   a. STOP all current work immediately
   b. Read the ENTIRE resource start to finish
   c. If it suggests a different approach → SWITCH to it, don't "adapt" your current one
   d. Only deviate AFTER the reference approach is confirmed working
   e. NEVER "glance" at a resource and continue your own approach
```

---

### PROMPT 1 — RECON (copy-paste this)

```
PHASE 0: RECON ONLY. Do NOT analyze source code or decompile functions yet. Just perform basic reconnaissance.

Do these steps and report findings (add more if u want):

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

**After AI reports back:** Read it. Understand the binary's protections and basic behavior. If there's a quick win (win function, no PIE + no canary), tell AI to try it immediately. Otherwise proceed to Prompt 2A.

---

### PROMPT 2A — STATIC ANALYSIS (copy-paste this)

⚠️ **This is STATIC ONLY. Ghidra MCP. No pwndbg. No running the binary. No scripts.**

```
PHASE 1A: STATIC ANALYSIS ONLY. Use Ghidra MCP exclusively. Do NOT run the binary or use pwndbg yet.

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

C. CONSTRAINTS ANALYSIS
   - What limits do I have? (buffer size, number of operations, filters)
   - What does each constraint SUGGEST about the intended approach?
   - What's NOT restricted that I can use?

D. INITIAL THEORY
   - Based on static analysis alone, what's your exploit theory?
   - What assumptions does your theory make that MUST be verified dynamically?
   - List exactly what GDB needs to confirm (addresses, offsets, layout)

Report to me:
1. Challenge overview (what it does, how to interact)
2. Each function explained clearly
3. ALL vulnerabilities found with primitives
4. Your initial exploit theory
5. A numbered list of ASSUMPTIONS that need GDB verification
```

**After AI reports back:** This is where YOU think critically. Ask yourself:
- Does the exploit theory make sense?
- Did AI consider ALL memory regions, or only the obvious target?
- Are there variables adjacent to the buffer that AI ignored?
- Did AI miss any bugs?
- Does the constraint analysis reveal the author's intent?

If anything seems off or incomplete, ask follow-up questions before proceeding.

**If heap challenge (malloc/free detected) → use Prompt 2.5 next.**
**If custom VM/interpreter → use Prompt 2.6 next.**
**Otherwise → proceed to Prompt 2B.**

---

### PROMPT 2.5 — HEAP-SPECIFIC ANALYSIS (use when heap operations detected)

```
PHASE 1.5: HEAP DEEP DIVE. The binary uses heap operations — we need precise heap analysis.

A. HEAP STATE MAPPING
   1. Run with GDB. After setup/allocations, run:
      - pwndbg> heap (show all chunks with addresses and sizes)
      - pwndbg> bins (show tcache, fastbin, unsorted, small, large bins)
      - pwndbg> tcache (show tcache counts per size)
   2. Draw the heap layout: where is each chunk? What's the tcache_perthread_struct?
   3. Note: first user chunk is typically at heap_base + 0x2a0 (after tcache struct)

B. SAFE-LINKING ANALYSIS (glibc 2.32+)
   1. Is safe-linking enabled? (Check glibc version)
   2. Verify: key for each chunk is chunk_addr >> 12 (NOT heap_base >> 12)
   3. For reading encrypted pointers, implement demangle_ptr():
      def demangle_ptr(v):
          r = v
          for _ in range(4): r = v ^ (r >> 12)
          return r

C. LIBC VERSION ANALYSIS
   1. What glibc version? (strings libc.so.6 | grep "GNU C Library")
   2. Are __malloc_hook / __free_hook available? (readelf -s libc.so.6 | grep hook)
   3. If hooks removed (2.34+): plan for FSOP / House of Apple 2 / House of Banana / Or Any possible Houses

D. FILE STRUCTURE ANALYSIS (if FSOP likely)
   1. Run: pwndbg> ptype struct _IO_FILE_plus
   2. Run: pwndbg> ptype struct _IO_wide_data
   3. Note critical offsets: _lock (0x88), _wide_data (0xa0), vtable (0xd8)
   4. Find _IO_list_all address: pwndbg> p &_IO_list_all
   5. Find a writable NULL qword for _lock field

E. OFFSET VERIFICATION
   - For EVERY offset: verify with GDB, not from blog posts or memory
   - Unsorted bin offset: p/x <leaked_value> - <libc_base> (calculate from YOUR libc)
   - Chunk addresses: use actual addresses from heap command

Report:
1. Complete heap layout diagram (addresses, sizes, chunk states)
2. Safe-linking parameters if applicable
3. Available heap exploitation techniques for this glibc version
4. FILE structure offsets if FSOP is the path
5. All verified offsets with GDB proof
```

**After AI reports back:** Verify the heap layout matches reality. Check that safe-linking keys use chunk addresses, not heap base. If FSOP is planned, ensure `_lock` field is included.

---

### PROMPT 2.6 — VM/INTERPRETER ANALYSIS (use when custom VM detected)

```
PHASE 1.6: CUSTOM VM DEEP DIVE. This binary implements a custom VM/interpreter.

A. INSTRUCTION SET DOCUMENTATION
   1. Document the COMPLETE instruction format:
      - How many bytes per instruction?
      - How are opcodes encoded? (raw? encrypted? XORed with key?)
      - What are the operand fields?
   2. Create a FULL opcode table with ALL handlers
   3. For EACH handler, document:
      - What it reads (registers, memory, state variables)
      - What it writes (registers, memory, state variables)
      - What SIDE EFFECTS it has (key mutations! flag changes! counter updates!)

B. STATE EVOLUTION TRACING
   ⚠️ THIS IS THE #1 VM FAILURE POINT.
   1. What state variables exist? (PC, key, flags, etc.)
   2. How does EACH opcode modify the state?
   3. Are there HIDDEN mutations? (e.g., ADD handler also XORs result into key)
   4. Trace 3-4 instructions by hand with pen-and-paper to verify understanding
   5. Set GDB breakpoints at dispatch to verify key/state after each instruction

C. MEMORY LAYOUT
   1. VM code region — where is bytecode loaded?
   2. VM data/heap region — where does STORE write to?
   3. Function pointer / dispatch table — where is it? Is it writable?
   4. What ELSE is near the VM memory? (function pointers, GOT entries, globals)

D. VULNERABILITY IDENTIFICATION
   1. Bounds checks: are they signed or unsigned? (jle vs jbe)
   2. What's the reach of an OOB write? (negative index → before buffer)
   3. Can we write to the dispatch table? GOT? Other function pointers?
   4. Calculate exact offset: target_addr - vm_memory_base

E. EXPLOIT TARGET SELECTION
   1. List ALL function pointer tables / dispatch entries
   2. For each: is there a magic number guard? What args does it receive?
   3. PREFER targets without guards (e.g., HALT handler with no validation)

Report:
1. Complete instruction set documentation
2. State evolution rules (especially key/encryption mutations)
3. Memory map showing VM regions and nearby writable targets
4. Identified vulnerability with exact primitive description
5. Recommended exploit target with justification
```

**After AI reports back:** The critical thing to verify is state evolution. Ask: "Show me the disassembly of the ADD handler — does it mutate any state beyond the result register?" If AI says key is simple addition, verify there's no XOR step hidden in the handler.

---

### PROMPT 2B — HYPOTHESIS VERIFICATION (copy-paste this)

⚠️ **This is TARGETED dynamic analysis. pwndbg MCP only. One hypothesis at a time.**

```
PHASE 1B: VERIFY YOUR ASSUMPTIONS. Use pwndbg MCP to test each assumption from your static analysis.

RULES — TOKEN DISCIPLINE:
- NO GDB scripts. Use pwndbg MCP directly.
- ONE hypothesis per debug session
- ONE breakpoint → ONE register/address read → hypothesis confirmed or killed → STOP
- State your hypothesis BEFORE setting the breakpoint

For each assumption you listed in Phase 1A:

1. State the hypothesis in one sentence:
   "I believe [X] is at [address/offset] because [reasoning from static analysis]"

2. Set ONE breakpoint at the exact instruction to verify it

3. Run with appropriate input

4. Read the MINIMUM data needed:
   - One register value, OR
   - One memory address (x/gx), OR
   - One stack frame dump (telescope)

5. Result: CONFIRMED ✓ or KILLED ✗
   - If confirmed → move to next hypothesis
   - If killed → update theory based on evidence, state new hypothesis

After verifying all assumptions, report:
1. Each hypothesis with result (✓/✗)
2. Updated memory layout diagram (with VERIFIED addresses)
3. Final exploit theory (updated based on verified facts)
4. Any remaining unknowns
```

**After AI reports back:** Check that EVERY assumption was verified, not assumed. If AI skipped verification for any step, ask: "Did you actually verify [X] in GDB, or are you assuming it?"

---

### PROMPT 3 — EXPLOIT STRATEGY (copy-paste this)

```
PHASE 2: EXPLOIT STRATEGY. Do NOT write code yet. Plan the full attack.

Based on your VERIFIED analysis, answer these questions:

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
1. Write one phase at a time (Do todolist). After each phase, verify it works before proceeding.
2. After each phase, print the obtained value with log.success() and verify:
   - Is the leaked address aligned? (heap = 0x5X, libc = 0x7f, stack = 0x7ff)
   - Does it match expected ranges?
3. For debugging: use pwndbg MCP directly (NO GDB scripts):
   - State what you expect to see BEFORE checking
   - Set ONE breakpoint → read ONE value → confirmed or find root cause
   - If the value is wrong: diagnose WHY before trying a fix
4. If ANY checkpoint fails: STOP. Tell me:
   - What you expected
   - What actually happened
   - Your hypothesis for WHY it's wrong
   Do NOT proceed blindly or try random variations.

Start with Phase 1 of our strategy. Show me the result before continuing.
```

**After AI reports Phase 1 works:** Tell it to proceed phase by phase:
```
Phase 1 looks good. Proceed to Phase 2.
```

**If something fails:**
```
That didn't work. DON'T write a debug script. Use pwndbg MCP directly:
1. Set a breakpoint at the EXACT instruction where the value is wrong
2. Read the register or memory address that should contain the expected value
3. Tell me: what's there instead? Why is it different from what we expected?
Do NOT try another variation until we understand the root cause.
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

   Critical questions (from real failures):
   - Am I using ALL provided leaks? Which ones am I ignoring?
     (Unused leak = missed attack vector!)
   - Have I verified ALL intermediate states, not just the final target?
     (Mid-instruction addresses, partial overwrites, temporary values)
   - Am I debugging root cause or just trying variations?
     (3-strike rule: after 3 failed attempts, STOP and diagnose with GDB)
   - What DATA STRUCTURES haven't I considered?
     (FILE struct, heap metadata, vtables, dispatch tables)
   - Is unexpected output (double prints, wrong values) telling me something?
     (Every output is a signal, not noise)
   - Have I been trying the same approach >3 times?
     If yes, MANDATORY STOP. Debug root cause before any more attempts.

   Think about what the challenge AUTHOR intended. What technique does
   the combination of protections + vulnerability + constraints point to?

Present 2-3 alternative approaches ranked by likelihood.
```

---

### PROMPT 6 — POST-MORTEM (use after solving or giving up)

```
PHASE 5: POST-MORTEM. Let's learn from this challenge.

Answer these questions honestly:

1. LEAK USAGE: Which leaks did we use? Which did we ignore? For ignored leaks,
   what technique would they have enabled?

2. APPROACH COUNT: How many times did we retry the same approach before pivoting?
   If >3, what should have triggered the pivot earlier?

3. ROOT CAUSES: For each failure during the exploit:
   - What was the symptom? (crash, wrong value, hang)
   - What was the root cause?
   - What debugging step would have found it fastest?

4. MISSED TECHNIQUES: What technique(s) did we NOT consider that would have worked?
   - Data structures we didn't target? (FILE, heap metadata)
   - Memory regions we didn't use? (.bss, writable globals)
   - Intermediate optimizations we missed? (func+1 entry, overlapping writes)

5. KEY LESSONS: What 2-3 things should we remember for next time?

Summarize as a checklist I can reference in future challenges.
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
✓ Ask "which leaks are we NOT using?" — every leak has a purpose
✓ Ask "have you checked intermediate states?" for bit flips and multi-step modifications
✓ Ask "what data structures could we target?" (FILE, heap metadata, vtables)
✓ Use Prompt 6 after EVERY challenge — learning compounds
✓ Watch for AI writing GDB scripts — interrupt immediately and say "use pwndbg MCP directly"
✓ If AI says "let me check with GDB", ask "what's your hypothesis? what breakpoint? what value?"

DON'T:
✗ Skip the analysis phase — this is where the exploit is born
✗ Let AI try 10 variations of a failing approach (enforce 3-strike rule)
✗ Accept "this should work" without seeing GDB proof
✗ Proceed to next phase without verifying current phase works
✗ Let AI overcomplicate an easy challenge
✗ Let AI oversimplify a hard challenge
✗ Accept hardcoded offsets from blog posts — verify with YOUR libc/binary in GDB
✗ Ignore unused leaks — they point to missed attack vectors
✗ Treat unexpected output as noise — it's diagnostic information
✗ Let AI write GDB Python scripts — this is the #1 token waste pattern
✗ Let AI "explore" in pwndbg without a stated hypothesis
```
