# CTF Challenge Environment

## Setup
- **OS:** Kali Linux with pwndbg MCP + Ghidra MCP
- **Exploit dev:** Python 3 with pwntools
- **Categories:** PWN, Rev, Crypto, Web, Forensics, Misc

## Methodology Files (READ BEFORE STARTING)
- **PWN:** Read `pwn-methodology.md` (rules) + `pwn-hybrid.md` (workflow prompts)
- **Rev:** Read `rev-methodology.md` (rules) + `rev-hybrid.md` (workflow prompts)

**⚠️ If a methodology file exists for the category, you MUST read it before doing anything.**

---

## TOKEN DISCIPLINE (applies to ALL categories)

### Ghidra-First Policy
- Exhaust ALL static analysis (Ghidra MCP) before using pwndbg
- Every question you CAN answer from decompilation → answer there (zero runtime cost)
- Only open pwndbg to VERIFY a specific hypothesis, never to "explore"

### No GDB Scripts — Ever
- NEVER write separate Python GDB scripts (gdb_debug.py, exploit_debug.py, etc.)
- Each script costs tokens to write → run → parse → usually wrong question → rewrite
- Use pwndbg MCP directly: 1 breakpoint → 1 register/address → 1 answer → stop

### Hypothesis-Driven Debugging
Before opening pwndbg, answer:
1. What is my hypothesis? (one sentence)
2. What instruction do I break at?
3. What register/address do I read?

If you can't answer all three → go back to Ghidra.

### 3-Strike Rule
After 3 failed attempts at the same approach → MANDATORY STOP. Do NOT try variation #4.
Go back to static analysis and re-examine assumptions.

---

## Writeup/Resource Protocol

When writeups, hints, or reference material are provided:
1. **STOP** all current work
2. **READ** the entire resource start to finish
3. If it suggests a different approach → **SWITCH** immediately
4. Only deviate AFTER the reference approach is confirmed working
5. **NEVER** "glance" at a resource and continue your own approach

---

## PWN Challenge Rules

### Phase Order (never skip)
1. **Recon** — checksec, file, strings, run binary, readelf
2. **Static Analysis** — Ghidra MCP only. Understand program, find ALL bugs, list assumptions
3. **Hypothesis Verification** — pwndbg MCP. Test each assumption: 1 breakpoint → 1 answer
4. **Exploit Strategy** — Plan full chain on paper. No code yet
5. **Implement** — Build incrementally, verify each phase with pwndbg before next

### Offset Verification
- EVERY offset must be verified in GDB with the provided libc/binary
- NEVER use offsets from blog posts, writeups, or memory
- `p/x leaked_value - known_base` → compute offset from YOUR binary

### Heap Challenges
- Safe-linking key = `chunk_addr >> 12` (NOT `heap_base >> 12`)
- Verify unsorted bin offset from YOUR libc: `p/x &main_arena - libc_base`
- If FSOP: include `_lock` field (writable NULL qword) or it will deadlock
- Guard chunk prevents top chunk consolidation

### Debugging Failures
- Unexpected output (double prints, wrong values) = diagnostic signal, not noise
- Unused leaks = missed attack vectors — audit ALL provided leaks
- If stuck: what data structures haven't I considered? (FILE struct, heap metadata, vtables)

---

## Rev Challenge Rules

### Phase Order
1. **Recon** — file type, strings, imports, entry point
2. **Static Analysis** — Ghidra MCP. Full decompilation, understand transformations
3. **Solve** — Write solver script based on static understanding
4. **Verify** — Test locally before submitting

### Key Principles
- Understand the transformation before writing code
- Look for known crypto patterns (XOR, AES, RSA, custom ciphers)
- Check for anti-debug, obfuscation, packing first

---

## General Rules

### Binary Protocol Challenges
- Pre-build packets as bytestrings in Python
- Feed via pwndbg `run_with_input` for debugging
- Track state variables (epoch, key, counter) faithfully

### Docker Challenges
- Read Dockerfile FIRST — it reveals syscall filters, available binaries, flag location
- Extract libc + ld-linux from container, patch binary with pwninit

### Flag Format
- Check challenge description for flag format (e.g., `CTF{...}`, `flag{...}`)
- Verify flag before submitting if possible

### Session Management
- Start each challenge by reading the relevant methodology file
- Log progress: what worked, what failed, what was learned
- Run post-mortem (Prompt 6 in pwn-hybrid.md) after every challenge
