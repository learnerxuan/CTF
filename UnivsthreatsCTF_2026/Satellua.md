# CTF Writeup: Satellua — Reverse Engineering

**Category:** Reverse Engineering  
**Difficulty:** Hard  
**Techniques:** Anti-Analysis, VM Evasion, PRNG Reversal (SplitMix64)  
**Flag:** `UVT{R3turn_8y_Thr0w_Del1v3r3r}`

---

## Challenge Overview

Satellua presents a custom, obfuscated **Lua 5.5** virtual machine executing a 9.5MB bytecode payload. The challenge is a psychological trap — reversing the custom Lua engine and decompiling the bytecode is a multi-week rabbit hole. The actual flag validation logic operates **entirely outside the VM**, utilizing Lua runtime errors (panics) to advance a cryptographic PRNG state. Every `N`-th error decrypts one byte of the flag.

The intended solve path: observe the binary's behavior, trace backward from the `Flag:` output string, identify the SplitMix64 PRNG by its magic constants, extract the encrypted bytes from the binary, and write an offline solver — never touching the 9.5MB bytecode at all.

---

## Phase 0: Reconnaissance & Dynamic Anomalies

Before opening a disassembler, observe the binary's behavior to form a hypothesis. Reversers who skip this step burn hours in the wrong direction.

### 1. Static Metadata

```bash
file satellua
# satellua: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

ls -lh satellua
# -rwxrwxr-x 1 xuan xuan 9.5M Feb 24 02:18 satellua
```

**Anomaly 1 — Unusual size:** A typical CTF reverse binary is under 100KB. At 9.5MB, this binary is carrying a massive embedded payload. Checking the ELF section headers confirms it:

```bash
readelf -S satellua | awk '{print $1, $2, $3, $4, $5, $6}' | grep -A 2 "\.data"
# [23] .data PROGBITS 00000000006302c0 000302c0
# 000000000094a857 0000000000000000 WA 0 0 32
```

The `.data` section alone is `0x94A857` bytes (~9.5MB). The ELF binary is a native C wrapper that carries and loads a compiled Lua bytecode blob.

### 2. Strings Extraction

```bash
strings satellua > strings.txt
grep -iE "lua|panic|flag" strings.txt
```

Key findings:

- `Lua 5.5` — a non-standard, custom-patched version of Lua (not the official release)
- `PANIC: unprotected error in call to Lua API (%s)` — the VM has a custom panic handler
- `invalid string index, attempt to divide by zero` — suspicious: this is an error message, not a user-facing string. Why is it hardcoded?
- `Flag: %s` — the flag output format
- `You enter the cycle once more..` — printed repeatedly during normal execution

> **Why the "divide by zero" string matters:** In a normal Lua script, runtime errors produce dynamic error messages. Hardcoding this specific error message implies it is being triggered **intentionally and repeatedly** by the Lua script as a control signal — not a bug.

### 3. Dynamic Tracing

Running the binary produces an infinite loop that ignores all input, periodically printing `"You enter the cycle once more.."`.

Tracing system calls reveals the true behavior:

```bash
strace -e clock_gettime ./satellua
```

```
clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {tv_sec=0, tv_nsec=107752735}) = 0
clock_gettime(CLOCK_PROCESS_CPUTIME_ID, {tv_sec=0, tv_nsec=107902231}) = 0
...
--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=4678 ...} ---
```

**Anomaly 2 — No blocking I/O:** The program fires millions of `clock_gettime` syscalls without ever calling `read()` or `scanf()`. There is no waiting for user input — it is executing a massive computation loop continuously in the background.

**Anomaly 3 — SIGCHLD:** The program is forking child processes. This is uncommon for a simple flag checker.

### Hypothesis After Recon

The 9.5MB `.data` section is a compiled Lua bytecode blob. The Lua script runs in an infinite loop and **intentionally throws runtime errors** (e.g., divide by zero) at high frequency. The C binary's custom panic handler catches each error, increments a counter, and every `N`-th error uses the current PRNG state to decrypt one byte of the flag. The flag is revealed character-by-character over millions of error cycles.

This means: **we never need to decompile or understand the Lua bytecode.** We only need the error handler's logic and the encrypted flag bytes.

---

## Phase 1: Static Analysis & The Red Herring

Loading `satellua` into Ghidra, the main setup function is straightforward:

```c
// Decompiled setup function
lVar2 = luaL_newstate();
if (lVar2 != 0) {
    luaL_openlibs(lVar2, 0xffffffff, 0);

    // Load the 9.5MB payload from .data
    iVar1 = luaL_loadbuffer(lVar2, &DAT_006302e0, PTR_DAT_006302c0, "savefile", 0);
    if (iVar1 == 0) {
        lua_pcall(lVar2, 0, 0, 0, 0, 0);  // Execute it
    }
}
```

At this point, many players extract `DAT_006302e0`, notice the custom header `\x1bSatelluaU\x01` (indicating a modified Lua bytecode format), and spend hours building a custom bytecode disassembler.

**This is the trap.** The custom Lua 5.5 VM has modified opcodes, a non-standard header, and 9.5MB of deliberately obfuscated bytecode. Fully reversing it is not the intended path.

> **The Reverser's Rule:** In a 48-hour CTF, if the "obvious" path requires a multi-week research effort, it is a red herring. Find the choke point — the minimal location where all the data flows through.

---

## Phase 2: Tracing the True Logic (The Pivot)

The choke point is the `Flag: %s` format string. We trace backward from it.

**In Ghidra:**
1. `Search → For Strings`
2. Search for `Flag: %s`
3. Check Cross-References (XREFs) → leads to `FUN_00405800`

### Analyzing the Error Handler (`FUN_00405800`)

This function is installed as the custom panic/error handler for the Lua VM. Every Lua runtime error triggers it.

```c
void FUN_00405800(long param_1, char param_2) {
    // param_1 = pointer to the VM state struct

    // Increment the global error counter
    uVar1 = *(int *)(param_1 + 0xd0) + 1;
    *(uint *)(param_1 + 0xd0) = uVar1;

    // THE DECRYPTION TRIGGER
    if (((ulong)uVar1 % 0x111088 == 0) && (*(uint *)(param_1 + 0xd4) < 0xf)) {

        // Step 1: Fetch the current 64-bit PRNG output from the Lua stack
        uVar3 = *(undefined8 *)(*(long *)(param_1 + 0x10) + -0x10);

        // Step 2: Collapse 8 bytes → 1 byte via XOR folding
        uVar8 = (uint)((ulong)uVar3 >> 0x20);
        uVar8 = (uint)(byte)((ulong)uVar3 >> 0x38) ^
                (uint)(ushort)((ulong)uVar3 >> 0x30) ^
                (uint)uVar3 ^
                uVar8 >> 8 ^
                uVar8 ^
                (uint)((ulong)uVar3 >> 0x18) ^
                (uint)((ulong)uVar3 >> 0x10) ^
                (uint)((ulong)uVar3 >> 8);

        // Step 3: XOR-decrypt one byte of the flag
        iVar2 = *(int *)(param_1 + 0xd4);
        *(byte *)(param_1 + 0xd8 + iVar2) = (byte)uVar8 ^ (&DAT_004227e0)[iVar2];

        // Step 4: Advance the index and print current decrypted flag
        *(int *)(param_1 + 0xd4) = iVar2 + 1;
        printf("Flag: %s\n", param_1 + 0xd8);
    }

    // longjmp back into the Lua VM to continue execution
}
```

**Breaking down the decryption logic:**

| Element | Value | Meaning |
| :--- | :--- | :--- |
| `param_1 + 0xd0` | Error counter | Incremented on every Lua runtime error |
| `0x111088` | 1,118,344 | One flag character is revealed every 1,118,344 errors |
| `param_1 + 0xd4` | Character index | Tracks how many flag bytes have been decrypted (max 0xf = 15) |
| `uVar3` | 64-bit PRNG state | Fetched from the Lua stack top (`[param_1+0x10] - 0x10`) |
| XOR collapse | 8 bytes → 1 byte | All 8 bytes of the 64-bit state are XOR-folded together |
| `DAT_004227e0` | Encrypted flag array | The ciphertext bytes stored in the binary |

The Lua script is intentionally written to throw millions of errors. Each error is a "tick." Every 1,118,344 ticks, one character of the flag is revealed by XOR-decrypting it with a byte derived from the current PRNG state.

### Identifying the PRNG

Tracing the source of `uVar3` backward through Ghidra's XREFs reveals the PRNG update function:

```c
z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
z = (z ^ (z >> 27)) * 0x94D049BB133111EB;
x = z ^ (z >> 31);
```

The state is advanced by adding the **golden ratio constant** before each round:

```c
z = x + 0x9E3779B97F4A7C15;  // additive constant (golden ratio)
```

Searching for `0xBF58476D1CE4E5B9` immediately identifies this as **SplitMix64** — a fast, high-quality 64-bit PRNG commonly embedded in Lua, Java's `ThreadLocalRandom`, and other runtimes.

> **Lesson:** Never reverse-engineer standard crypto/hashing algorithms from scratch. Search the magic constants first. SplitMix64's constants (`0xBF58476D1CE4E5B9`, `0x94D049BB133111EB`) are unique identifiers.

The initial PRNG seed is `0x1fff000`, found as the hardcoded starting value in Ghidra.

---

## Phase 3: Data Extraction

We need the encrypted bytes at `DAT_004227e0`. Since the binary has no PIE (base `0x400000`), the file offset is:

```
0x4227e0 - 0x400000 = 0x227e0
```

```bash
dd if=satellua bs=1 skip=$((0x227e0)) count=48 2>/dev/null | xxd -p
```

Output:

```
640daef1be1f6cf53801f3e507e0986df4fd4e2000fd46dfc4fa0d4dc2ac
00007661726961626c65202725732720676f
```

The bytes immediately following `c2ac` decode as `variable '%s' go` — this is the adjacent string literal section in the binary's data, confirming we have hit the boundary of the encrypted flag array.

The encrypted flag ciphertext is exactly:

```
64 0d ae f1 be 1f 6c f5 38 01 f3 e5 07 e0 98 6d f4 fd 4e 20 00 fd 46 df c4 fa 0d 4d c2 ac
```

30 bytes — consistent with the flag format `UVT{R3turn_8y_Thr0w_Del1v3r3r}` (30 characters).

---

## Phase 4: Solver Construction

We now have every primitive needed to bypass the 9.5MB VM entirely:

- **PRNG algorithm:** SplitMix64 with seed `0x1fff000`
- **Byte collapse formula:** XOR-fold all 8 bytes of the 64-bit state
- **Trigger interval:** Every `0x111088` PRNG advances = one flag character
- **Encrypted bytes:** 30 bytes from file offset `0x227e0`

The solver auto-syncs to the correct phase offset by searching for the expected first character `U` (from the `UVT{` flag prefix) near the expected threshold.

```python
#!/usr/bin/env python3

def get_collapsed_byte(val):
    """
    Replicates the C bit-shifting collapse logic from FUN_00405800.
    XOR-folds all 8 bytes of a 64-bit integer into a single byte.
    """
    res = 0
    for _ in range(8):
        res ^= (val & 0xFF)
        val >>= 8
    return res

# Extracted from file offset 0x227e0 (virtual address 0x4227e0)
hex_dump = "640daef1be1f6cf53801f3e507e0986df4fd4e2000fd46dfc4fa0d4dc2ac"
enc_bytes = [int(hex_dump[i:i+2], 16) for i in range(0, len(hex_dump), 2)]

# Constants extracted from Ghidra
GOLDEN_RATIO  = 0x9E3779B97F4A7C15   # SplitMix64 additive increment
HIT_INTERVAL  = 0x111088             # 1,118,344 errors per flag character
INITIAL_STATE = 0x1fff000            # Seed found in binary

print("[*] Simulating SplitMix64 PRNG sequence (takes ~3–5 seconds)...")

x = INITIAL_STATE
flag = ""
steps_taken = 0

# ──────────────────────────────────────────
# Phase 1: Auto-sync — find the exact step
#           where first byte decrypts to 'U'
# ──────────────────────────────────────────
while True:
    # SplitMix64 step
    z = (x + GOLDEN_RATIO) & 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
    z &= 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 27)) * 0x94D049BB133111EB
    z &= 0xFFFFFFFFFFFFFFFF
    x = z ^ (z >> 31)
    steps_taken += 1

    # Search within ±5 steps of the expected interval
    if HIT_INTERVAL - 5 <= steps_taken <= HIT_INTERVAL + 5:
        if get_collapsed_byte(x) ^ enc_bytes[0] == ord('U'):
            print(f"[+] Synced at step {steps_taken}!")
            flag += 'U'
            break

# ──────────────────────────────────────────
# Phase 2: Decrypt remaining characters
# ──────────────────────────────────────────
for k in range(1, len(enc_bytes)):
    # Advance PRNG by exactly HIT_INTERVAL steps
    for _ in range(HIT_INTERVAL):
        z = (x + GOLDEN_RATIO) & 0xFFFFFFFFFFFFFFFF
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
        z &= 0xFFFFFFFFFFFFFFFF
        z = (z ^ (z >> 27)) * 0x94D049BB133111EB
        z &= 0xFFFFFFFFFFFFFFFF
        x = z ^ (z >> 31)

    collapsed = get_collapsed_byte(x)
    dec_char  = chr(enc_bytes[k] ^ collapsed)
    flag     += dec_char

    if dec_char == '}':
        break

print(f"\n[+] FLAG: {flag}")
```

### Execution

```bash
$ python3 solve.py
[*] Simulating SplitMix64 PRNG sequence (takes ~3–5 seconds)...
[+] Synced at step 1118343!

[+] FLAG: UVT{R3turn_8y_Thr0w_Del1v3r3r}
```

---

## Vulnerability / Logic Summary

| Phase | Technique | What We Did |
| :--- | :--- | :--- |
| Recon | `strace`, `strings`, `readelf` | Identified 9.5MB payload, infinite error loop, no blocking I/O |
| Red herring avoidance | XREF tracing from `Flag: %s` | Skipped the 9.5MB bytecode entirely; went straight to the error handler |
| PRNG identification | Magic constant search | Identified SplitMix64 via `0xBF58476D1CE4E5B9` |
| Data extraction | `dd` with computed file offset | Dumped 30 encrypted bytes from `0x227e0` |
| Offline solver | SplitMix64 emulation + XOR-fold | Fully replicated the binary's decryption logic in Python |

---

## Key Concepts to Remember

**What is SplitMix64 and why is it used here?**
SplitMix64 is a fast, statistically high-quality 64-bit PRNG. It is commonly embedded in Lua's internal math library as the default random number generator. The challenge exploits the fact that Lua's PRNG state is deterministic from a known seed — the C error handler can reproduce the same sequence offline. Identifying it by its constants (`0xBF58476D1CE4E5B9`, `0x94D049BB133111EB`) is the intended step.

**What does "XOR folding" mean in this context?**
The PRNG produces a 64-bit integer. The flag decryption needs only a 1-byte XOR key. The collapse function splits the 64 bits into 8 consecutive bytes and XOR-folds them together: `byte[0] ^ byte[1] ^ ... ^ byte[7]`. This loses entropy (multiple 64-bit states could produce the same byte) but is perfectly deterministic from a known state sequence.

**Why does the Lua script throw intentional errors?**
The error counter is the only synchronization mechanism between the Lua bytecode and the C error handler. The script cannot call the C decryption function directly — it operates inside the VM sandbox. By throwing exactly `N * 0x111088` errors, the bytecode controls when the C layer reveals each flag character. This is a form of **covert channel** communication between two trust boundaries (VM sandbox ↔ native host).

**What is `lua_pcall` vs `lua_call`?**
`lua_call` lets Lua errors propagate unhandled — they crash the host program. `lua_pcall` (protected call) catches Lua errors and returns an error code, allowing the host to handle them gracefully. By using `lua_pcall`, the C binary intercepts every Lua runtime error without crashing, feeding them into the counter. The custom panic handler installed via `lua_atpanic` is an additional catch layer for errors that escape even `pcall`.

**Why did `auto-sync` need a ±5 step search window?**
The PRNG state at the exact trigger is `x` *after* the `HIT_INTERVAL`-th step. Depending on whether the counter starts at 0 or 1 (off-by-one in C vs. our Python sim), the exact hit may occur at step `HIT_INTERVAL - 1` or `HIT_INTERVAL`. The ±5 window accounts for minor alignment ambiguity without requiring us to re-read the assembly more carefully.

**Why is `0x9E3779B97F4A7C15` called the "golden ratio constant"?**
The value `0x9E3779B97F4A7C15` is the 64-bit approximation of `2^64 / φ` where `φ` ≈ 1.618 (the golden ratio). Adding an irrational-scaled constant on each step ensures the additive sequence has maximum period and good bit distribution — a technique called **Weyl sequences** in PRNG theory. You will see this exact constant in SplitMix64, PCG, and many other modern PRNGs.

**Why does extracting from file offset `0x227e0` work?**
When PIE is disabled (base `0x400000`), the virtual address of a symbol directly encodes its file offset: `file_offset = virtual_address - 0x400000`. So `0x4227e0 - 0x400000 = 0x227e0`. This relationship only holds for non-PIE binaries. For PIE binaries, you would need to read the ELF program headers to compute the actual file offset from the load segment's `p_offset` and `p_vaddr`.
