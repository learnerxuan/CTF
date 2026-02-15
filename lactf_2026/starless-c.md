# LACTF 2026 — `rev/starless-c` Writeup (Beginner-Friendly, Evidence-Based)

> **Challenge:** `rev/starless-c`  
> **Prompt:** “The son of the fortune-teller stands before three doors. A bee. A key. A flag.”  
> **Remote:** `nc chall.lac.tf 32223`  
> **Flag:** `lactf{starless_c_more_like_starless_0xcc}`

This writeup is written for **future-me** and for beginners. It includes **every key command**, **why we ran it**, and **how to interpret the results**, including the exact confusion points I had (e.g., `starti`, `info proc mappings`, why `find` didn’t work, and why some addresses are “Cannot access memory”).

---

## Table of Contents

- [0. Mindset & Methodology](#0-mindset--methodology)
- [1. Phase 0 — Recon & Classification](#1-phase-0--recon--classification)
- [2. Phase 1 — Dynamic Analysis Setup](#2-phase-1--dynamic-analysis-setup)
  - [2.1 What is `starti`?](#21-what-is-starti)
  - [2.2 What is `info proc mappings`?](#22-what-is-info-proc-mappings)
- [3. Phase 2 — Identify the Flag Printing Routine](#3-phase-2--identify-the-flag-printing-routine)
- [4. Phase 3 — Understand One “Room” Page](#4-phase-3--understand-one-room-page)
  - [4.1 Commands and what they mean](#41-commands-and-what-they-mean)
  - [4.2 The room handler template (input → dispatch)](#42-the-room-handler-template-input--dispatch)
  - [4.3 The “key/token” mechanic (stateful maze)](#43-the-keytoken-mechanic-stateful-maze)
  - [4.4 Why `f` is special](#44-why-f-is-special)
- [5. Phase 4 — Common Debugging Confusions (and fixes)](#5-phase-4--common-debugging-confusions-and-fixes)
- [6. Solving Strategy](#6-solving-strategy)
  - [6.1 Manual solve (what I did)](#61-manual-solve-what-i-did)
  - [6.2 Automated solve (recommended for learning)](#62-automated-solve-recommended-for-learning)
- [7. Final Solve (Remote)](#7-final-solve-remote)
- [8. Summary of What This Challenge Teaches](#8-summary-of-what-this-challenge-teaches)

---

## 0. Mindset & Methodology

This is **not** a standard “compare input to string” crackme. It’s a “gimmick” ELF that behaves like a **maze** built out of **executable pages**.

Reverse engineering mindset:

1. **Find where the flag is printed**
2. **Find the win condition** (what state triggers the jump to flag code)
3. **Model the computation** (rooms + moves + state transitions)
4. **Solve** (manual or BFS)

---

## 1. Phase 0 — Recon & Classification

### Commands

```bash
ls -lah
file starless_c
checksec --file=./starless_c || true
strings -n 5 ./starless_c | grep -iE "flag|door|bee|key|win|lose|lactf" | head
./starless_c
```

### Findings

- `file`:
  - `ELF 64-bit LSB executable, x86-64, statically linked, no section header`

This is a **weird ELF**: “no section header” means many static tools are less helpful; runtime observation becomes very valuable.

- `checksec`:
  - `NX disabled` ⇒ **executable memory can also be writable** (RWX). This is *very unusual* in normal binaries, but perfect for “self-modifying / VM / maze pages” gimmicks.

- Running binary prints:

```
There is a flag in the binary.
  (The flag is a metaphor but also still a flag.)
  (The binary could rightly be considered a gimmick.)
```

So the author is literally telling us: this is a **gimmick**, likely **runtime code pages**.

---

## 2. Phase 1 — Dynamic Analysis Setup

I used `pwndbg` because it makes memory mapping and disassembly easier.

### Commands

```bash
pwndbg ./starless_c
```

Inside GDB/pwndbg:

```gdb
starti
info proc mappings
```

---

### 2.1 What is `starti`?

**My confusion:** “What does `starti` do and why use it?”

- `starti` starts the program and stops at the **first instruction** (the ELF entry point).
- Unlike `start` (which tries to reach `main`), `starti` doesn’t need symbols and works well for stripped/weird binaries.

So `starti` is a strong default for RE when there’s no `main` / no symbols / weird ELF layout.

---

### 2.2 What is `info proc mappings`?

**My confusion:** “What is `info proc mappings` and why do we care?”

- It prints the process memory layout (similar to `/proc/<pid>/maps`).
- This tells us what pages exist and their permissions (`r-xp`, `rwxp`, etc).
- In this challenge, it reveals multiple **RWX pages** → huge clue this is a “maze made of code pages”.

Example output pattern:

```
0x13370000 ... r-xp  starless_c
0x42069000 ... r-xp  starless_c
0x67679000 ... rwxp  starless_c
0x6767a000 ... rwxp  starless_c
... many more rwxp pages ...
```

Interpretation:

- `0x13370000`: entry-ish code (prints intro text)
- `0x42069000`: **special executable page** (later we prove it prints the flag)
- `0x6767xxxx`: **many RWX pages** = rooms/maze logic

---

## 3. Phase 2 — Identify the Flag Printing Routine

We saw a clean executable page:

- `0x42069000 - 0x4206a000  r-xp`

So we disassembled it:

```gdb
x/80i 0x42069000
```

### What we found (proof)

We saw syscalls:

- `eax = 1` → `write(1, ..., 0xe0)` prints story text
- `eax = 2` → `open("flag.txt", O_RDONLY)`
- `eax = 0x28` → `sendfile(1, fd, NULL, 0x100)` outputs the file
- `eax = 0x3c` → `exit(0)`

So **jumping to `0x42069000` prints the flag**.

#### Note about `find "flag.txt"` not working

I tried:

```gdb
find 0x42069000, 0x4206a000, "flag.txt"
```

and got:

- warning about “Unable to access 4097 bytes…”
- “Pattern not found.”

Fixes:

1) `find` end address is **inclusive**, so searching to `0x4206a000` reads 4097 bytes. Correct range is:

```gdb
find 0x42069000, 0x42069fff, "flag.txt"
```

2) It still may not find because the string is embedded as instruction immediates, and GDB `find` often treats `"flag.txt"` like a C-string needing `\0`.

Better: search exact bytes:

```gdb
find /b 0x42069000, 0x42069fff, 0x66,0x6c,0x61,0x67,0x2e,0x74,0x78,0x74
```

---

## 4. Phase 3 — Understand One “Room” Page

From mappings, pages like `0x67679000` and `0x6767a000` are `rwxp`. We treat each such page as a **room**.

### 4.1 Commands and what they mean

#### Examine raw bytes at start of page
```gdb
x/16bx 0x67679000
```

- `x` = examine memory
- `/16` = 16 units
- `b` = bytes
- `x` = hex output

We saw bytes like:

```
31 c0 88 00 ... cc cc cc cc ...
```

`31 c0 88 00` disassembles to:

- `xor eax,eax`
- `mov byte ptr [rax], al` → write to address 0 → **crash**

And `0xcc` is `int3` (breakpoint trap).

So the **page base is a “trap/door-state area”**, not the normal handler.

#### Disassemble the actual handler (page+0xC)
```gdb
x/200i 0x6767900c
```

---

### 4.2 The room handler template (input → dispatch)

This is the same across rooms:

1) **Read 1 byte** from stdin:
```asm
xor eax,eax        ; syscall 0 = read
xor edi,edi        ; fd=0
mov rsi,rsp        ; buf=rsp
mov edx,1
syscall
mov al,[rsi]
```

2) Ignore newline:
```asm
cmp al,0xa
je read_again
```

3) Compare against allowed keys:
- `0x77` `'w'`
- `0x61` `'a'`
- `0x73` `'s'`
- `0x64` `'d'`
- `0x66` `'f'`

If invalid key → intentional crash:
```asm
xor eax,eax
mov BYTE PTR [rax],al
```

So input alphabet is exactly: **`w a s d f`**

---

### 4.3 The “key/token” mechanic (stateful maze)

A move block for `w/a/s/d` follows a pattern:

```asm
mov eax, DWORD PTR [target_base]
cmp al, 0x90
jne skip
mov DWORD PTR [target_base], 0x88c031
mov DWORD PTR [dest_base], eax
skip:
jmp target_base+0xc
```

#### What does that mean?

- The first byte of `target_base` is checked:
  - If it is `0x90` (NOP), then “the key/token is present in this room”
- If key is present:
  - overwrite `target_base`’s first 4 bytes with crash-stub `0x88c031` (bytes `31 c0 88 00`) → “consume/remove the key there”
  - copy the old 4-byte header to `dest_base` → “move the key to dest”

So **the maze has state**: which room pages start with `0x90`.

This is why the solve is not just a simple path through a graph. The state is:

> `(current_room, token_distribution)`

where `token_distribution` can be modeled as a bitmask over rooms.

---

### 4.4 Why `f` is special

For `w/a/s/d`, rooms jump to `target+0xc` (handler).

For `f`, we saw patterns like:

```asm
jmp 0x6767a000    ; page BASE, not +0xc
```

So `f` jumps to the **door-state area** at the page base. Normally the base starts with crash bytes, so `f` would kill you.

But if the correct pages have been transformed so their base starts with NOPs, the base can become a “safe door” that chains/jumps to the flag page `0x42069000`.

---

## 5. Phase 4 — Common Debugging Confusions (and fixes)

### (A) “Why does `find` warn about 4097 bytes?”
Because `find` uses an inclusive end address. Use `end = start + 0x1000 - 1` for a single page.

### (B) “Why does `find ... 0x77` say not found even though I see `cmp al,0x77`?”
Use byte search:

```gdb
find /b START, END, 0x77
```

Without `/b`, GDB may interpret values as word-sized.

### (C) “Why does `x/4bx 0x67672000` say cannot access memory?”
Because the page may **not be mapped**. In this puzzle, some move targets are “walls” / invalid rooms.

Also: don’t paste multiple GDB commands on one line unless separated by semicolons:

```gdb
x/4bx 0xAAA; x/4bx 0xBBB; x/4bx 0xCCC
```

### (D) “Why does `catch syscall read` stop with weird bytes in AL?”
The handler reads into `rsp`. Before your actual keystroke arrives, the stack may still contain old printed text, so `[rsp]` can show random/old bytes. After you type, it will read your input.

---

## 6. Solving Strategy

### 6.1 Manual solve (what I did)

I connected remote:

```bash
nc chall.lac.tf 32223
```

Then sent a long sequence of `w/a/s/d` and ended with `f`.

The service printed the “final path” story and then the flag, meaning the `f` action successfully triggered the door chain to `0x42069000`.

Example successful input (as observed):

```
sddddswaasdwaaasdssawwdwddsawasassdddwsddwasaaaawwdwdddsawaasassdddwwdwasssaaawwdwwassdddssddwasaaawwddwdsaaawdsassddwsddwawaawasdddssawdwaaddwaaf
```

### 6.2 Automated solve (recommended for learning)

**Why automate?**  
Because the maze is stateful. The clean approach is:

1) parse all rooms → edges `(w/a/s/d)` each gives `(target, dest)`
2) track a bitmask of which room-bases currently have `0x90`
3) BFS over `(room, mask)` until the required door pages have `0x90`, then press `f`

This is the “computation understanding” approach: turn assembly into a state machine.

---

## 7. Final Solve (Remote)

```bash
nc chall.lac.tf 32223
# paste the move string ending with 'f'
```

Output includes the flag:

`lactf{starless_c_more_like_starless_0xcc}`

---

## 8. Summary of What This Challenge Teaches

- **Runtime mappings matter.** When ELF is weird (“no section header”), rely on:
  - `starti`
  - `info proc mappings`
  - direct disassembly via `x/i`

- **RWX pages are a massive clue.**
  - RWX almost always means: custom VM, JIT, self-modifying gimmick, or “maze pages”.

- **Convert assembly into a model:**
  - Rooms = pages
  - Moves = transitions
  - State = which pages start with NOP (`0x90`)
  - `f` = “try door base” (special control-flow)

- **Don’t guess; validate.**
  - We proved the flag routine by disassembling `0x42069000` and identifying syscalls.

---

## Appendix: Useful pwndbg/GDB commands reference

```gdb
# Start at first instruction
starti

# Show memory mappings (critical for weird ELF / RWX pages)
info proc mappings

# pwndbg nicer mapping view (if available)
vmmap

# Disassemble N instructions at address
x/80i 0xADDR
x/200i 0xADDR

# Dump raw bytes (byte-level)
x/16bx 0xADDR
x/4bx 0xADDR

# Search memory (byte search is safest)
find /b 0xSTART, 0xEND, 0x90
find /b 0xSTART, 0xEND, 0x66,0x6c,0x61,0x67,0x2e,0x74,0x78,0x74

# Disable pagination
set pagination off

# Break on syscalls (useful to stop when input loop begins)
catch syscall read
run
```

---

> If you’re redoing this later:  
> Start with `starti` → `info proc mappings` → disassemble the unique executable page(s) like `0x42069000` → then disassemble a room handler at `room+0xc` and recover the move mechanics.
