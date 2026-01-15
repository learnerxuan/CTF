# Court Jester - CTF Reverse Engineering Writeup

## Challenge Description

> I reside as the Queen of this data kingdom. Prithee, I implore you to remedy the ailments of our poor beloved court jester. In the days since he imbibed an entire cask of old mead I suspect was fermented from a bad batch of barley microkernels, he has not been himself and, well, juggles data all wrong! Help us I plead, our kingdom depends on YOU, traveller!

**Category:** Reverse Engineering
**Flag:** `RUSEC{i_suppos3_you_0utjuggl3d_me_LKNGFU389XYVGTS7ONLEU4DMK}`

---

## Phase 1: Initial Reconnaissance

Before doing anything complex, always ask: **"What is this thing?"**

### Step 1.1: Check File Type

```bash
file court_jester
```

**Output:**
```
court_jester: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), statically linked, no section header
```

**Analysis:**

| Finding | What It Means |
|---------|---------------|
| `ELF 64-bit` | Linux executable, 64-bit |
| `statically linked` | All code is inside the binary (no external .so libraries) |
| `no section header` | ⚠️ **UNUSUAL** - someone stripped it to make analysis harder |

### Step 1.2: Run the Binary

```bash
./court_jester
```

**Output:**
```
              (0x2c) -
                        '
                         '
                @_  _    '
                 )\/(@    '
               __(/ \--._
              (,-.---'--'@
               @ )0_0(     _
                 ('-')    (_)
            '    _\Y/_
            ' .-'-\-/-'-._  '
            _ /    '*      '
           (_)  /)  *    .-.))>'
             ._/  \__*_ /\__'.
         '<((_'    |__H/  \__\
                   /   ,_/ |_|
                   )-- /   |x|
                   \ _/    (_ x
                   /_/       \_\@
                  /_/
                 /_/
                /x/
               (_ x
                 \_\@

.,, ., ,, ,  ,.,, (0x2c) ,,.,   .,  ,. . .,,
```

**Key Observations:**

1. **ASCII art of a jester** - matches the challenge theme
2. **`(0x2c)` appears TWICE** - once in the jester area, once at the bottom
3. **`0x2c` in hex = 44 in decimal = `,` (comma character)**
4. **Bottom line has dots and commas** - looks like encoded data

> **Hacker Mindset:** "If something looks out of place, it's probably important." The `(0x2c)` displayed prominently is NOT decoration - it's a hint!

---

## Phase 2: System Call Tracing

The program runs and exits quickly. But **how** does it work internally?

### What is strace?

| Tool | Purpose |
|------|---------|
| `strace` | **System call trace** - shows every syscall (read, write, open, fork, etc.) |
| `ltrace` | **Library trace** - shows library function calls |

`strace` lets you see what the program asks the operating system to do.

### Step 2.1: Run strace

```bash
strace -f ./court_jester 2>&1 | head -100
```

**Flags explained:**
- `-f` = follow child processes (if the program forks)
- `2>&1` = redirect stderr to stdout (strace outputs to stderr)
- `head -100` = show first 100 lines

### Step 2.2: Understanding strace Output

Every line shows: **"The program asked the OS to do something"**

Format:
```
syscall_name(arguments) = return_value
```

Example:
```
open("/etc/passwd", O_RDONLY) = 3
```
Means: "Program asked to open /etc/passwd for reading, OS gave file descriptor 3"

### Step 2.3: Key Findings from strace

#### Finding 1: Two Pipes Created

```
pipe2([3, 4], 0) = 0
pipe2([5, 6], 0) = 0
```

**What is a pipe?**
```
A pipe is like a tube for data:

   Writer ───────────────► Reader
          (data flows)

fd 4 (write end) ──────► fd 3 (read end)   ← Pipe #1
fd 6 (write end) ──────► fd 5 (read end)   ← Pipe #2
```

Two pipes = **two-way communication channel**

#### Finding 2: Process Forks

```
clone(child_stack=NULL, flags=...SIGCHLD, ...) = 8751
strace: Process 8751 attached
```

The program creates a **child process**. Now we have:
- Parent process (original)
- Child process (PID 8751)

#### Finding 3: Parent and Child Communicate

**Round 1:**
```
[pid 8750] write(6, "\264\310\265\330...", 20)           ← Parent SENDS 20 bytes
[pid 8751] read(5, "\264\310\265\330...", 20)            ← Child RECEIVES same bytes
[pid 8751] write(4, "~y\177ioWEs_Y\\\\C_\37sUCYs", 20)   ← Child RESPONDS
[pid 8750] read(3, "~y\177ioWEs_Y\\\\C_\37sUCYs", 20)    ← Parent RECEIVES response
```

**Round 2:**
```
[pid 8750] write(6, "\312\220\216\217...", 20)           ← Parent SENDS
[pid 8751] write(4, "\34YXFYKK@\37HsAIs`gbkjy", 20)      ← Child RESPONDS
```

**Round 3:**
```
[pid 8750] write(6, "\265\23\277s...", 20)               ← Parent SENDS
[pid 8751] write(4, "\37\24\25tuzkx\177\33cb`iy\30hagQ", 20) ← Child RESPONDS
```

### Visual Diagram

```
     PARENT (8750)                         CHILD (8751)
          │                                     │
          │  write(6, encrypted_data)           │
          │ ──────────────────────────────────► │
          │           (via pipe #2)             │ read(5, encrypted_data)
          │                                     │
          │                                     │ [processes/transforms data]
          │                                     │
          │                                     │ write(4, response)
          │ ◄────────────────────────────────── │
          │  read(3, response)                  │
          │           (via pipe #1)             │
```

### Summary of Data Exchange

| Round | Parent Sends (encrypted) | Child Responds |
|-------|-------------------------|----------------|
| 1 | `\264\310\265\330...` | `~y\177ioWEs_Y\\C_\37sUCYs` |
| 2 | `\312\220\216\217...` | `\34YXFYKK@\37HsAIs`gbkjy` |
| 3 | `\265\23\277s...` | `\37\24\25tuzkx\177\33cb`iy\30hagQ` |

**Total: 3 responses × 20 bytes = 60 bytes**

---

## Phase 3: Decoding the Flag

### The Connection

We have:
1. **Child responses:** 60 bytes of data
2. **The hint:** `(0x2c)` shown prominently
3. **`0x2c`** = 44 = comma `,`

**Hypothesis:** What if we XOR the child responses with `0x2c`?

### What is XOR?

XOR (exclusive or) is a reversible operation:
```
A XOR B = C
C XOR B = A  ← back to original!
```

If data is encrypted with XOR, we decrypt by XORing with the same key.

### Why Combine All 3 Responses?

| Observation | Conclusion |
|-------------|------------|
| Flags are typically 40-60 characters | Need more than 20 bytes |
| 3 responses × 20 bytes = 60 bytes | Combine them! |
| They happen in sequence (1→2→3) | Order matters |

> **Hacker Mindset:** "If data comes in chunks, try combining them in order."

### Step 3.1: Python Script to Decode

```python
#!/usr/bin/env python3

# The 3 child responses from strace
child1 = b"~y\x7fioWEs_Y\\\\C_\x1fsUCYs"
child2 = b"\x1cYXFYKK@\x1fHsAIs`gbkjy"
child3 = b"\x1f\x14\x15tuzkx\x7f\x1bcb`iy\x18hagQ"

# Combine all responses (they come in sequence)
all_data = child1 + child2 + child3

# The hint from the jester output
key = 0x2c

# XOR each byte with the key
decoded = bytes([b ^ key for b in all_data])

# Print the flag
print(decoded.decode())
```

### Step 3.2: Run the Script

```bash
python3 solve.py
```

**Output:**
```
RUSEC{i_suppos3_you_0utjuggl3d_me_LKNGFU389XYVGTS7ONLEU4DMK}
```

---

## Key Lessons Learned

### 1. Follow the Hints

The `(0x2c)` was displayed **prominently** in the output. In CTFs, nothing is accidental. If something stands out, it's probably important.

### 2. Use strace for Unknown Binaries

When you don't know what a binary does:
```bash
strace -f ./binary 2>&1 | less
```

Look for:
- `fork()` / `clone()` - process creation
- `pipe()` / `pipe2()` - inter-process communication
- `read()` / `write()` - data transfer
- `open()` - file access
- `connect()` / `send()` / `recv()` - network activity

### 3. Don't Overcomplicate

I initially spent time:
- Analyzing the packing mechanism
- Dumping unpacked code
- Trying Morse code interpretations

**None of this led to the flag.**

The actual solution was simple:
1. `strace` to see pipe communication
2. XOR child responses with `0x2c`
3. Done!

> **Rule:** If you spend 30+ minutes on a path with no flag-related data, step back and try a different approach.

### 4. Understand the Challenge Theme

The description said the jester "juggles data all wrong." This hinted that:
- Data is being transformed/juggled between processes
- The child process is the key (it "juggles" the data)

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify binary type |
| `strace -f` | Trace system calls, follow forks |
| Python | XOR decryption |

---

## Alternative: One-Liner Solution

If you already know the technique:

```bash
strace -f ./court_jester 2>&1 | grep "write(4" | head -3
```

Then decode with Python:
```python
print(bytes([b ^ 0x2c for b in b"~y\x7fioWEs_Y\\\\C_\x1fsUCYs" + b"\x1cYXFYKK@\x1fHsAIs`gbkjy" + b"\x1f\x14\x15tuzkx\x7f\x1bcb`iy\x18hagQ"]))
```

---

## Flag

```
RUSEC{i_suppos3_you_0utjuggl3d_me_LKNGFU389XYVGTS7ONLEU4DMK}
```

The flag text "i_suppos3_you_0utjuggl3d_me" references the jester being "outjuggled" - we decoded his juggled data!

Official Source: https://github.com/scarlet-ctf/writeups/tree/main/2026/REV/court_jester
