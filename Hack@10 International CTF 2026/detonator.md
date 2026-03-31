# detonator — Detailed CTF Writeup

**Challenge:** detonator
**Category:** Reverse Engineering
**Flag Format:** `HACK10{}`
**Flag:** `HACK10{be029cf0e9f2eaa5f80489343630befb}`

---

## Challenge Description

> In malware analysis, you can either statically analyze the assembly codes directly, or you can create a snapshot of your sandbox and detonate it inside.

The description is a hint at the two valid solution paths:
- **Dynamic:** run the binary inside a properly configured Windows sandbox
- **Static:** reverse the logic and compute the result without executing

We take the static path.

---

## Phase 0 — File Identification

```bash
file detonator.exe
# detonator.exe: PE32+ executable (console) x86-64, for MS Windows, 19 sections

md5sum detonator.exe
# 8d3c43023feb53a830c823af5fa321c0

sha256sum detonator.exe
# 171b4295ed77388da5e0009729eedfbaa7764c3e52ee25ddd6590bc64ea845b2

wc -c detonator.exe
# 284430 bytes
```

Key observations from PE headers:
- **Architecture:** x86-64
- **Subsystem:** Windows CUI (console application)
- **Toolchain:** MinGW (GCC for Windows) — confirmed by `__mingw_snprintf`, libstdc++ symbols, and `__gxx_personality_seh0`
- **Protections:** PIE (`DYNAMIC_BASE`), `HIGH_ENTROPY_VA`, `NX_COMPAT`
- **NOT .NET** — no `mscoree.dll` import, no CLR directory

---

## Phase 1 — String Triage

The first thing to do with any binary is dump strings.

```bash
strings detonator.exe | grep -iE "(hack|flag|here|local|path|found)"
```

This immediately reveals two high-signal strings:

```
C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt
HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}
Here is the flag: HACK10{
File not found. Keep looking...
```

The fake flag `HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}` is embedded **as a Windows username** inside a file path. This is the first misdirection — the string in `{}` braces is not the real flag. The program uses this path to locate a file, and the presence of `Here is the flag: HACK10{` tells us the real flag is computed at runtime.

Additional imports of note:
- `stat64i32` — used for file existence checking
- `Sleep` — anti-analysis timing (not used in the main flag path)
- `VirtualQuery`, `VirtualProtect` — memory inspection (runtime relocator boilerplate, not challenge logic)
- `strncmp`, `strlen` — string operations
- `std::cout` — output

---

## Phase 2 — Ghidra Analysis

Loading into Ghidra (headless) identifies **168 functions**. The non-boilerplate, challenge-specific functions stand out immediately:

| Address | Name | Role |
|---|---|---|
| `0x140001b7e` | `main` | Entry point |
| `0x1400019cf` | `check_flag` | Core logic |
| `0x140001450` | `md5` | Hash computation |

---

## Phase 3 — `main` Decompilation

```c
int __cdecl main(int _Argc, char **_Argv, char **_Env)
{
    __main();       // MinGW runtime init
    check_flag();
    return 0;
}
```

`main` does nothing but call `check_flag()`. All logic is there.

---

## Phase 4 — `check_flag` Decompilation

```c
void check_flag(void)
{
    // Build the file path string
    std::string local_78 =
        "C:\\Users\\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\\Desktop\\local.txt";

    // Build the (unused) fake flag string
    std::string local_98 =
        "HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}";

    // Check whether the file exists
    struct stat local_c8;
    int iVar1 = stat64i32(local_78.c_str(), &local_c8);

    if (iVar1 == 0) {
        // File exists — compute and print the real flag
        std::cout << "Here is the flag: HACK10{";
        std::string hash = md5(local_78);   // hash of the PATH STRING
        std::cout << hash << "}\n";
    } else {
        // File does not exist
        std::cout << "File not found. Keep looking...\n";
    }
}
```

Key observations:

1. **`stat64i32`** only checks if the file *exists*. It never opens or reads the file.
2. **`local_98`** (the fake flag string) is constructed but never used in any computation. It is pure misdirection.
3. **`md5(local_78)`** is called with the **path string itself** — `local_78` — not the file contents.
4. The output is `Here is the flag: HACK10{` + md5 result + `}`.

The "detonation" interpretation: if you create a Windows user account named `HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}` and place any file at `Desktop\local.txt`, the binary will print the flag. But the path string is fully hardcoded, so we don't need to detonate anything.

---

## Phase 5 — `md5` Analysis

### 5a. Initialization Constants

```c
local_1c = 0x67452301;   // A
local_20 = 0xefcdab89;   // B
local_24 = 0x98badcfe;   // C
local_28 = 0x10325476;   // D
```

These are the **standard MD5 initialization vectors** from RFC 1321. No modification.

### 5b. Round Functions

The loop runs 64 iterations split into four rounds of 16, matching the standard MD5 round structure:

| Rounds | Function | Index schedule |
|---|---|---|
| 0–15 | `F(B,C,D) = (B & C) \| (~B & D)` | `i` |
| 16–31 | `G(B,C,D) = (D & B) \| (~D & C)` | `(5i + 1) % 16` |
| 32–47 | `H(B,C,D) = B ^ C ^ D` | `(3i + 5) % 16` |
| 48–63 | `I(B,C,D) = C ^ (B \| ~D)` | `(7i) % 16` |

Decompiled directly:

```c
if (local_50 < 0x10) {
    local_54 = ~local_44 & local_4c | local_44 & local_48;   // F
    local_58 = local_50;
} else if (local_50 < 0x20) {
    local_54 = ~local_4c & local_48 | local_4c & local_44;   // G
    local_58 = (local_50 * 5 + 1) % 0x10;
} else if (local_50 < 0x30) {
    local_54 = local_44 ^ local_48 ^ local_4c;               // H
    local_58 = (local_50 * 3 + 5) % 0x10;
} else {
    local_54 = (~local_4c | local_44) ^ local_48;            // I
    local_58 = (local_50 * 7) % 0x10;
}
```

All four round functions match RFC 1321 exactly.

### 5c. Output Formatting (Assembly Verification)

The Ghidra decompiler showed only one argument being passed to `snprintf` for the format string `"%02x%02x%02x%02x"`, which would be incorrect. Inspecting the actual assembly at `0x1400018b0` resolves this:

```asm
; For each of the 4 hash words (local_b8[0..3]):
MOV EAX, dword ptr [RBP + RAX*4 + 0x30]   ; load hash word
SHR EAX, 0x18                              ; byte 3 (>>24) → R8D  → [RSP+0x30]
MOV EAX, dword ptr [RBP + RAX*4 + 0x30]
SHR EAX, 0x10 / MOVZX ECX,AL              ; byte 2 (>>16) → ECX  → [RSP+0x28]
MOV EAX, dword ptr [RBP + RAX*4 + 0x30]
SHR EAX, 0x8  / MOVZX EDX,AL              ; byte 1 (>>8)  → EDX  → [RSP+0x20]
MOV EAX, dword ptr [RBP + RAX*4 + 0x30]
MOVZX R10D,AL                              ; byte 0 (>>0)  → R9D  (4th arg)

; Windows x64 calling convention:
; RCX=buf, RDX=9, R8=format, R9=byte0, [RSP+0x20]=byte1, [RSP+0x28]=byte2, [RSP+0x30]=byte3
CALL __mingw_snprintf
```

The bytes are extracted in order `byte0, byte1, byte2, byte3` (i.e., least-significant to most-significant), which is standard **little-endian MD5 hex output**. This matches Python's `hashlib.md5(...).hexdigest()` exactly.

### 5d. Conclusion

The `md5()` function is an **unmodified standard MD5** implementation. No custom constants, no modified round functions, no altered output encoding.

---

## Phase 6 — Determining the Input

The call in `check_flag`:

```c
md5(local_48, local_78);
```

`local_78` is the `std::string` holding the file path. Inside `md5()`:

```c
std::string local_a8(param_2);   // copy of local_78
local_68 = local_a8.size();      // length of the path string
// ... standard MD5 padding and compression ...
```

The input is the raw bytes of the path string (ASCII, no null terminator), which is:

```
C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt
```

Length: **75 bytes**.

---

## Phase 7 — Solve

```python
import hashlib

path = r"C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt"
md5_hash = hashlib.md5(path.encode()).hexdigest()
print(f"HACK10{{{md5_hash}}}")
```

Output:
```
HACK10{be029cf0e9f2eaa5f80489343630befb}
```

---

## Summary of Misdirections

The challenge plants several deliberate distractions:

| Decoy | Reality |
|---|---|
| `HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}` appears in strings | This is the fake flag. It only appears as a username in the hardcoded path. |
| `local_98` constructs the fake flag string | This variable is never used in any computation. |
| The file `local.txt` seems important | The file is only checked for existence. Its contents are never read. |
| "Detonation" implies you must execute the binary | The path string is fully static; no execution needed. |
| `Sleep`, `VirtualQuery`, `VirtualProtect` imports suggest anti-analysis | These are MinGW runtime boilerplate, not used in the flag path. |

---

## Dynamic Alternative (for completeness)

To solve via "detonation" on a Windows sandbox:

1. Create a local Windows user account with username `HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}`
2. Log in as that user (or create the path manually)
3. Create any file at `C:\Users\HACK10{f4k3_fl4g_bu7_y0u_4r3_in_7h3_righ7_7r4ck}\Desktop\local.txt`
4. Run `detonator.exe`
5. The program prints the flag directly

Both approaches yield the same result because the path string is hardcoded.

---

## Flag

```
HACK10{be029cf0e9f2eaa5f80489343630befb}
```
