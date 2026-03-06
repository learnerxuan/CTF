bit_flip:
🎓 POST-MORTEM: What I Did Wrong & Lessons Learned                                                                                                                                                                                          
                                                                                                                                                                                                                                            
  ❌ Critical Mistakes I Made                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
  1. TUNNEL VISION - The Biggest Mistake                                                                                                                                                                                                      
                                                                                                                                                                                                                                              
  What I did:
  - Calculated 0x1422 → 0x1429 needs bits 0,1,3
  - Assumed this was THE solution
  - Kept trying to make it work despite repeated failures
  - Never questioned if there was a BETTER approach

  What I missed:
  - Intermediate values 0x1423 and 0x1421 are in the middle of instructions
  - Should have checked: objdump -d main | grep 1423: → NO VALID INSTRUCTION
  - Alternative: cmd+1 (0x142a) with just ONE flip (bit 3)

  Lesson: When something fails repeatedly, STOP and re-evaluate. Don't force a broken approach.

  ---
  2. Ignored the Heap Leak

  What I did:
  - Used PIE leak ✓
  - Used stack leak ✓
  - Used libc leak ✓
  - Completely ignored heap leak ✗

  What I missed:
  - Heap leak was THE KEY to finding the FILE struct
  - FILE struct at sbrk(NULL) - 0x20cf0 is predictable
  - Challenge gave 4 leaks - each one has a purpose!

  Lesson: If the challenge gives you a leak, USE IT. All provided information is intentional.

  ---
  3. Didn't Think About Data Structures

  What I did:
  - Focused only on code: return addresses, ROP gadgets, code pointers
  - Mentioned FILE pointer briefly but didn't pursue it
  - Never explored what's INSIDE the FILE struct

  What I missed:
  - FILE struct exploitation (FSOP) is a classic technique
  - _fileno field at offset +0x70 controls which FD to read from
  - Flipping 2 bits: 3 (file) → 0 (stdin) redirects input!

  Lesson: Think beyond code. Data structures (FILE, heap chunks, GOT, vtables) are valid targets.

  ---
  4. Didn't Verify Intermediate States

  What I did:
  - Verified first two flips with GDB: 0x22→0x23→0x21 ✓
  - Never checked: "What instruction is at 0x1423?"
  - Assumed if final result is valid, intermediate values are fine

  What I missed:

  1422: b8 00 00 00 00    mov eax, 0x0  ← valid
  1423: 00 00 00 00 5d    [GARBAGE]     ← INVALID!
  1424: 00 00 00 5d       [GARBAGE]     ← INVALID!
  1429: 55                push rbp      ← valid


  Lesson: Verify EVERY step, not just the endpoint. Check all intermediate values.

  ---
  5. Poor Debugging Methodology

  What I did:
  - Saw SIGSEGV crash → tried another variation
  - Saw crash again → tried yet another variation
  - Never stopped to find ROOT CAUSE

  What I should have done:
  1. Attach GDB to crashed process
  2. Find exact instruction that crashes: movzx eax, BYTE PTR [rax]
  3. Check what address it's trying to access
  4. Understand WHY that address is invalid
  5. Trace back to root cause: "I'm jumping into middle of instruction"

  Lesson: When debugging, find the ROOT CAUSE, not just symptoms. Use GDB systematically.

  ---
  6. Didn't Understand Function Entry Points

  What I did:
  - Assumed cmd() MUST be called at cmd+0 (the push rbp)
  - Never considered entering at cmd+1, cmd+2, etc.

  What I missed:
  - cmd+1 skips push rbp but lands at mov rbp, rsp
  - This works because vuln already does leave; ret:
  vuln:
    leave        ; mov rsp, rbp; pop rbp (rbp restored)
    ret          ; pop rip → jump to cmd+1

  cmd+1:
    mov rbp, rsp ; set up frame (works even without push!)
    sub rsp, 0x30

  Lesson: Understand calling conventions deeply. Function prologue can sometimes be skipped.

  ---
  7. Didn't Study the Challenge Constraints

  What I did:
  - Saw "3 bit flips" → just treated as limitation
  - Saw "4 leaks" → used some, ignored others
  - Saw "cmd() unreachable" → focused on redirecting to it

  What I should have thought:
  - Why exactly 3 flips? (Not 2, not 4)
    - Suggests solution uses ALL 3 optimally
    - 2 flips for one thing + 1 flip for another?
  - Why give heap leak? (FILE struct!)
  - Why is cmd() unreachable but FILE pointer set up? (Need to redirect!)

  Lesson: Constraints are HINTS. Challenge design points to intended solution.

  ---
  🎯 What I Missed Completely

  The Elegant Solution Pattern:

  Flip 1: FILE._fileno bit 0  →  3 → 2
  Flip 2: FILE._fileno bit 1  →  2 → 0 (stdin)
  Flip 3: Return addr bit 3   →  0x1422 → 0x142a (cmd+1)

  Total: 3 flips
  Result: cmd() reads from stdin, executes our commands


  This is elegant because:
  - Uses exactly 3 flips (not wasteful)
  - Each flip has a purpose
  - All intermediate states are valid
  - Uses ALL 4 leaks (PIE, stack, heap, libc)

  ---
  📝 Checklist for Next Time

  Before Starting:

  - Read challenge completely - what's the vulnerability?
  - What protections are enabled? (each one rules out some techniques)
  - What leaks are provided? (each one enables something)
  - What's the constraint? (limited writes, limited flips, etc.)
  - What's unusual? (unreachable functions, weird setup, etc.)

  During Analysis:

  - Enumerate ALL possible approaches (code, data, heap, FILE, etc.)
  - For each approach, check: "Do I have the leaks needed?"
  - Use ALL provided information - don't ignore leaks
  - Check intermediate states, not just final result
  - Verify assumptions with GDB before coding

  When Stuck:

  - STOP trying variations of the same broken approach
  - Attach GDB and find EXACT crash location
  - Understand ROOT CAUSE, not just symptoms
  - Re-enumerate alternatives
  - Ask: "What am I missing? What haven't I explored?"

  Common Exploitation Techniques to Consider:

  - Return address manipulation (ROP, ret2func)
  - FILE struct exploitation (FSOP, _fileno, _IO_FILE)
  - Heap exploitation (tcache, fastbin, consolidation)
  - GOT overwrite (if Partial RELRO)
  - Function pointer hijacking
  - Format string attacks
  - Integer overflow/underflow
  - Stack pivoting
  - One gadget (if libc known)

  ---
  🧠 Mental Models to Internalize

  1. "What Can I Control?"

  Not just code pointers:
  - Return addresses
  - Function pointers
  - Data structure fields (FILE._fileno!)
  - Heap metadata
  - Size/length fields
  - Flags/booleans

  2. "What's Adjacent?"

  Memory is continuous:
  - What's next to my buffer?
  - What's near the overflowed data?
  - What else is in this struct?

  3. "All Intermediate Values Matter"

  When modifying values:
  - Check ALL intermediate states
  - Ensure each step is valid
  - One invalid state = crash

  4. "Leaks Are Hints"

  If challenge gives a leak:
  - PIE leak → need to find code gadgets
  - Stack leak → need to write to stack
  - Heap leak → need to exploit heap structures
  - Use ALL of them

  ---
  🎖️  Key Takeaway

  I was 90% there - I correctly:
  - ✅ Identified the vulnerability (bit flip primitive)
  - ✅ Found the target (cmd function)
  - ✅ Parsed all leaks
  - ✅ Calculated addresses correctly
  - ✅ Understood the goal (redirect to cmd)

  But I failed because:
  - ❌ Didn't verify intermediate instruction addresses
  - ❌ Didn't explore FILE struct manipulation
  - ❌ Didn't use the heap leak
  - ❌ Got stuck in tunnel vision

  The Solution Was:
  - 2 flips on FILE struct (heap) + 1 flip on return (stack)
  - Not 3 flips on return address

  ---
  💡 The Most Important Lesson

  When stuck, don't try harder on the same approach. Try DIFFERENTLY.

  Next time:
  1. Stop after 2-3 failed attempts
  2. Debug to find root cause
  3. Step back and enumerate ALL alternatives
  4. Check what I'm NOT using (unused leaks = clue!)
  5. Think: "What technique haven't I considered?"

  This challenge taught me to think more broadly about exploitation targets and to debug systematically rather than guess-and-check.


67 Challenge: 
What I did wrong (Key mistakes):                          
                               
  1. Wrong UNSORTED_BIN_OFFSET: I guessed 0x21a6a0 but correct is 0x1e7b20 - should always verify with GDB                                                                                                                                    
  2. Didn't demangle heap pointers: Forgot that safe-linking needs recursive XOR decryption (demangle_ptr() function)                                                                                                                         
  3. Wrong read_note() implementation: Read until \n instead of reading until menu (1. Create), causing hangs and wrong data
  4. Forgot _lock field: FILE structure needs _lock at offset 0x88 or it crashes
  5. Wrong heap address calculation: Assumed chunk0 = heap_base + small offset, but didn't account for tcache_perthread_struct (~0x290 bytes at start)
  6. Wrong safe-linking encryption: Used heap_key instead of note7_addr >> 12 - encryption key must be the chunk's own address, not heap base
  
Chaos:
Post-Mortem: What I Did Wrong

  1. Wrong Exploit Target (Fundamental Strategy Error)

  The biggest miss — I targeted dispatch_table[6] the whole time. When I disassembled it and found:

  if (rdi == 0xdeadc0de) → system("echo stub")
  else → printf("DEBUG: System @ %p", system_ptr)


  I should have immediately abandoned this as the target and looked for a better one. Instead, I kept trying to make opcode 6 work. The double "DEBUG: System @" I was seeing was proof that my instructions were decoding to garbage — opcode
   6 being hit twice by accident — but I didn't read that signal correctly.

  The correct target was func_table[0] (HALT handler), which has no magic number guard. Once overwritten, any HALT instruction triggers system().

  2. Wrong ADD/XOR Key Evolution

  The formula I had in exploit.py:
  self.key = ((result & 0xFF) + 0x13) & 0xFF   # WRONG
  Should have been:
  self.key = ((self.key ^ (result & 0xFF)) + 0x13) & 0xFF  # CORRECT
  The handler internally does chaos ^= result_lo before returning. I disassembled the handler and saw the xor eax, ecx instruction but didn't fully trace that it was mutating the chaos byte in-place before the interpreter loop added
  +0x13. This cascaded — every single instruction after the first ADD was encoded with a wrong key.

  3. Didn't Discover the Overlapping STORE Trick

  I built large values by doubling with ADD (DBL), e.g.:
  vm.SET(4, 0xFF)
  vm.DBL(4, 8)   # 8x ADD: R4 <<= 8
  This works but burns instructions quickly. The overlapping STORE trick (write 0xFF at offsets 0–7, then LOAD the QWORD) is far more elegant and gets you 0xFFFFFFFFFFFFFFFF in 10 instructions. I never thought of using memory as a scratch
   pad for value construction — I was thinking purely in terms of register arithmetic.

  4. GDB Dynamic Analysis Collapsed Early

  When the static analysis wasn't giving me answers fast enough, I tried to set up breakpoints with commands ... continue ... end blocks. The pwndbg MCP got stuck waiting for the interactive end prompt and the session became unusable.
  Instead of pivoting quickly, I spent time trying to recover it. I should have recognized sooner that multiline GDB commands don't work through the MCP and switched to single-command analysis.

  5. Didn't Correlate the "Two DEBUG prints" to Key Corruption

  The output was:

  DEBUG: System @ 0x7f...
  DEBUG: System @ 0x7f...
  [!] System Halted.


  Two calls to opcode 6's handler. This was a clear signal that my bytecode was decoding to completely wrong instructions — the key was wrong from the first ADD onwards, so random opcodes were being executed, two of which happened to hit
  handler 6. I treated it as a minor anomaly instead of the smoking gun it was.