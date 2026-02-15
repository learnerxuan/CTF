## HYBRID WORKFLOW — Reverse Engineering (Human + AI with Claude Code)

**How to use this:** First, input the `rev-methodology.md` file as context. Then use the prompts below one at a time. Read and understand each AI response before proceeding. You are the brain; AI is your tool.

---

### PROMPT 1 — RECON (copy-paste this)

```
PHASE 0: RECON ONLY. Do NOT decompile or analyze code yet.

Do these steps and report findings:

1. List all provided files (ls -la, file *)
2. For each file: file type, architecture, stripped?, language indicator
3. Check if packed: strings binary | grep -i upx, check entropy
4. If packed: unpack first (upx -d or note that memory dump is needed)
5. Run the binary with sample inputs (test, AAAA, flag_format{test})
   - What does it prompt for? What output does it give?
   - Does it need argv, stdin, or file input?
6. Search for obvious strings:
   - strings binary | grep -iE "flag|CTF|correct|success|wrong|invalid"
   - strings binary | grep -E "\{.*\}"
7. checksec binary (note protections, even if less important for RE)
8. readelf -S binary (note section addresses, sizes)

CLASSIFY this challenge:
- Native binary / Python bytecode / Java / WASM / Script / Other?
- Crackme / Algorithm reversal / Custom VM / Obfuscated / Multi-layer?

Report format:
- All files and their types
- Whether packed or obfuscated
- What the program does when run
- Challenge classification
- Any interesting strings found
- Flag format if discoverable
```

**After AI reports back:** Do you understand what kind of challenge this is? If it's a simple crackme with `strcmp`, tell AI to just break on `strcmp` in GDB and extract the answer. Otherwise proceed to Prompt 2.

---

### PROMPT 2 — DEEP ANALYSIS (copy-paste this)

```
PHASE 1: DEEP STATIC + DYNAMIC ANALYSIS. This is the most critical phase.

Use Ghidra MCP (or appropriate decompiler) and pwndbg MCP.

A. FULL PROGRAM UNDERSTANDING
   1. Decompile main() and every function it calls
   2. For EACH function: explain what it does, its parameters, its return value
   3. Draw the FULL program flow:
      input → [step 1] → [step 2] → ... → comparison → success/failure
   4. What data structures exist? (arrays, structs, lookup tables, grids)
   5. Where is the success condition? What triggers "Correct!"?

B. VALIDATION LOGIC (the most important part)
   - WHERE is user input compared/checked?
   - WHAT is it compared against? (hardcoded bytes? computed value? multiple checks?)
   - HOW is input transformed before comparison?
     - XOR? What key? What order?
     - Lookup table? Extract the full table
     - Custom algorithm? Show the full decompiled logic
     - Multiple stages? Show each stage
   - Is input length checked? What length?

C. DATA EXTRACTION (extract ALL relevant data)
   - Encrypted/encoded flag bytes: exact offset, exact hex values
   - Key arrays or lookup tables: full contents
   - Constants used in computation
   - Format strings with parameters
   - If stack-constructed: show the exact mov/movabs instructions and offsets
     (watch for overlapping writes!)

D. ARCHITECTURE ANALYSIS
   - Is there self-modifying code? (mmap RWX + copy from .data?)
   - Does it fork? (parent-child interaction via ptrace?)
   - Is there a mode switch? (Heaven's Gate: push 0x23; retf)
   - Is there a custom VM? (dispatch loop with opcode switch?)
   - Is there anti-debugging? (ptrace, timing, integrity checks?)

Report to me:
1. Program overview and flow diagram
2. Validation architecture type (Direct/Transform/Constraint/VM/etc.)
3. All extracted data (hex bytes, keys, tables)
4. The complete transform algorithm (pseudocode or decompiled code)
5. Your proposed solving strategy
6. Any uncertainties or things you couldn't resolve
```

**After AI reports back:** This is where YOU think critically:
- Does the algorithm explanation make sense? Walk through it mentally
- Did AI extract ALL the data, or just some of it?
- Is there data at OTHER offsets AI might have missed?
- Does the challenge name/description hint at something AI didn't consider?
- Are there overlapping stack writes that affect extracted values?

Ask follow-up questions before proceeding.

---

### PROMPT 3 — SOLVE STRATEGY (copy-paste this)

```
PHASE 2: SOLVE STRATEGY. Plan the exact approach before writing code.

Based on your analysis:

1. STRATEGY SELECTION:
   A. Direct extraction (GDB breakpoint on comparison)
   B. Algorithm reversal (write mathematical inverse)
   C. Per-byte brute force (each position independent? test this!)
   D. Constraint solving (Z3/SAT)
   E. Custom VM emulation (build emulator first)
   F. Dynamic analysis (monkey-patch, trace, emulate with Unicorn)
   G. Multi-layer extraction (unpack, then re-analyze)

2. JUSTIFY your choice:
   - Why this strategy and not another?
   - Is per-byte independence possible? (test: change byte 0, does only output 0 change?)
   - Is Z3 needed or is direct reversal simpler?
   - Do we need emulation because static analysis can't follow the code?

3. SOLVER DESIGN:
   - What data do you need to extract from the binary?
   - What is the exact algorithm your solver will implement?
   - What edge cases might trip us up? (endianness, overlapping writes, off-by-one, null terminators)

4. SANITY CHECK:
   - Does the solver output need to match a known format? (flag prefix/suffix)
   - How will we verify the output is correct?

Present the strategy. I will review and approve before you code.
```

**After AI presents strategy:** Verify it makes sense. If you think a different approach would work better, say so now.

---

### PROMPT 4 — WRITE SOLVER (copy-paste this)

```
PHASE 3: WRITE AND RUN THE SOLVER.

Rules:
1. Write a clean, commented solver script
2. Print intermediate values so I can verify each step
3. Run the solver and show the output
4. Verify: feed the solution BACK to the binary — does it print "Correct!"?

If the solver uses emulation (Unicorn):
- Allocate at least 1MB stack (deep call chains crash with small stacks)
- Print each found character as you go
- Show total runtime

If verification fails:
- STOP
- Show what the solver produced vs what the binary expects
- Use GDB to trace one character through the algorithm
- Show me the step-by-step comparison

Show me the flag.
```

---

### PROMPT 5 — WHEN STUCK (use when needed)

```
STOP. The current approach isn't working. Let's reassess.

1. Show me exactly what failed and why
2. Don't try another variation of the same approach. Instead ask:

   - Am I analyzing the RIGHT comparison target?
     * Scan ALL data regions for potential target arrays
     * Is there a SECOND stage after the one I found?

   - Am I using the RIGHT tool?
     * Would dynamic analysis solve what static can't?
     * Would Unicorn emulation be faster than reversing?
     * Would monkey-patching intercept the answer directly?
     * Does using angr (symbolic execution) just solve this?

   - Am I in a RABBIT HOLE?
     * Am I reversing obfuscation when I could just observe behavior?
     * Am I fighting anti-debug when I could extract everything statically?
     * Am I reversing the entire program when only one function matters?

   - Did I miss the AUTHOR'S HINT?
     * Re-read challenge name and description
     * What technique does the challenge name suggest?

Present 2-3 alternative approaches ranked by likelihood.
```

---

### TIPS FOR THE HYBRID WORKFLOW

```
DO:
✓ Read and UNDERSTAND AI's algorithm explanation before approving
✓ Ask "did you extract ALL data blocks?" after analysis
✓ Ask "is each byte position independent?" before committing to strategy
✓ Walk through the algorithm mentally with a test character
✓ Check the challenge name for hints about intended technique
✓ Use Prompt 5 EARLY if AI is going in circles

DON'T:
✗ Let AI spend 30 min on static deobfuscation — use Unicorn
✗ Accept "I extracted the encrypted array" without seeing the hex bytes
✗ Let AI fight anti-debugging when static extraction would work
✗ Skip verification — ALWAYS feed solution back to binary
✗ Assume the first comparison target is the right one
✗ Let AI overcomplicate what a simple GDB breakpoint could solve
```
