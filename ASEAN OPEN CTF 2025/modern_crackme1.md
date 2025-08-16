# Modern Crackme 1 - CTF Writeup

## Challenge Information
- **Name:** modern_crackme1
- **Category:** Reverse Engineering
- **Flag Format:** `flag{md5}`
- **Binary Type:** Mach-O 64-bit ARM64 executable (macOS)
- **Language:** Rust

## Initial Analysis

### File Inspection
```bash
┌──(xuan㉿kali)-[~/random]
└─$ file modern_crackme1  
modern_crackme1: Mach-O 64-bit arm64 executable, flags:<NOUNDEFS|DYLDLINK|TWOLEVEL|PIE|HAS_TLV_DESCRIPTORS>

┌──(xuan㉿kali)-[~/random]
└─$ ./modern_crackme1  
zsh: exec format error: ./modern_crackme1
```

The binary is a macOS ARM64 executable that cannot be run directly on Kali Linux. This means we need to use **static analysis** techniques to solve the challenge.

### Attempted Dynamic Analysis
```bash
# QEMU emulation failed
┌──(xuan㉿kali)-[~/random]
└─$ qemu-aarch64 ./modern_crackme1
Error while loading /home/xuan/random/modern_crackme1: Exec format error
```

Since dynamic analysis isn't feasible, we proceed with static reverse engineering using Ghidra.

## Static Analysis with Ghidra

### Finding the Entry Point

Opening the binary in Ghidra, we find the entry function:

```c
void entry(int param_1,undefined8 param_2)
{
  std::rt::lang_start(modern_crackme1::main,(long)param_1,param_2,0);
  return;
}
```

The presence of `std::rt::lang_start` immediately indicates this is a **Rust binary**. The actual main function is `modern_crackme1::main`.

### Analyzing the Main Function

The main function reveals several key components:

1. **Anti-debug protection**
2. **Command-line interface with multiple commands**
3. **State machine logic**
4. **Hidden functions for different commands**

Key code structure:
```c
// Anti-debug check
uVar2 = anti_debug_check();
if ((uVar2 & 1) == 0) {
    StateMachine::new(auStack_740);
    local_704 = 0;
} else {
    std::process::exit(1);
}

// Command processing loop with various commands:
// help, crypto, nasa, gov, corp, secret, status
```

### Command Analysis

The binary accepts several commands:
- `help` - Shows available commands
- `crypto` - Calls `fake_hidden_crypto_vault()`
- `nasa` - Calls `fake_hidden_nasa_codes()`
- `gov` - Calls `fake_hidden_gov_secrets()`
- `corp` - Calls `fake_hidden_corp_data()`
- **`secret`** - Calls `real_hidden_function()` ⭐
- `status` - Shows system status
- `quit/exit` - Exit program

## Discovering the Real Target

### The Real Hidden Function

The most interesting function is `real_hidden_function()`, which has conditional logic:

```c
if ((REAL_TRIGGER & 1) == 0) {
    _<>::to_string(param_1,&DAT_10004c18d,0xe);
} else {
    // Flag generation code!
    alloc::vec::Vec<T>::new(auStack_318);
    // ... builds "flag" string and formats with MD5
}
```

The flag is only generated when `REAL_TRIGGER = 1`. Otherwise, it returns a default denial message.

## Reverse Engineering the State Machine

### StateMachine::process Analysis

The key to setting `REAL_TRIGGER = 1` lies in the `StateMachine::process` function:

```c
byte __rustcall modern_crackme1::StateMachine::process(long param_1,undefined8 param_2,undefined8 param_3)
```

This function implements a 4-state finite state machine (0→1→2→3) with specific transition conditions:

#### State 0 → State 1
```c
if (iVar1 == 0) {
    lVar2 = core::str::_<impl_str>::len(param_2,param_3);
    if (lVar2 == 6) {
        // Check if 3rd character (index 2) is 'c'
        local_154 = core::iter::traits::iterator::Iterator::nth(local_150,2);
        uVar3 = *<>::eq(&local_154,"c");
        if ((uVar3 & 1) != 0) {
            *(undefined4 *)(param_1 + 0x30) = 1;  // Set state to 1
            *(uint *)(param_1 + 0x34) = *(uint *)(param_1 + 0x34) + 0x10;  // Counter += 0x10
        }
    }
}
```
**Condition:** Input length = 6, 3rd character = 'c'  
**Command:** `secret` ✅

#### State 1 → State 2
```c
if (iVar1 == 1) {
    uVar3 = core::str::_<impl_str>::contains(param_2,param_3,&DAT_10004be9d,3);
    if (((uVar3 & 1) != 0) && (*(uint *)(param_1 + 0x34) >= 0x10)) {
        *(undefined4 *)(param_1 + 0x30) = 2;  // Set state to 2
        *(uint *)(param_1 + 0x34) = *(uint *)(param_1 + 0x34) * 2;  // Counter *= 2
    }
}
```
**Condition:** Input contains 3-char string at `&DAT_10004be9d`

#### State 2 → State 3
```c
uVar3 = core::str::_<impl_str>::starts_with(param_2,param_3,&DAT_10004bec5,1);
if ((uVar3 & 1) != 0) {
    uVar3 = core::str::_<impl_str>::len(local_168,local_160);
    if (4 < uVar3) {
        *(undefined4 *)(param_1 + 0x30) = 3;  // Set state to 3
        *(uint *)(param_1 + 0x34) = *(uint *)(param_1 + 0x34) + 0x100;  // Counter += 0x100
    }
}
```
**Condition:** Input starts with 1-char string at `&DAT_10004bec5` AND length > 4

#### State 3 → SUCCESS
```c
if (iVar1 == 3) {
    uVar3 = core::cmp::impls::_<>::eq(&local_168,&PTR_DAT_1000641a8);
    if (((uVar3 & 1) != 0) && (*(int *)(param_1 + 0x34) == 0x120)) {
        local_155 = 1;
        REAL_TRIGGER = 1;  // 🎯 SUCCESS!
    }
}
```
**Condition:** Input exactly matches string at `&PTR_DAT_1000641a8` AND counter = 0x120 (288)

### Extracting String Constants

Using Ghidra's memory viewer to examine the referenced addresses:

#### DAT_10004be9d (State 1 condition)
```
10004be9d: 72 65 74  → "ret"
```

#### DAT_10004bec5 (State 2 condition)  
```
10004bec5: 73  → "s"
```

#### PTR_DAT_1000641a8 → DAT_10004be5f (State 3 condition)
```
10004be5f: 75 6e 6c 6f 63 6b  → "unlock"
```

## Solution Sequence

### State Machine Progression

Based on the analysis, the required command sequence is:

1. **`secret`** → State 0→1 (length=6, 3rd char='c', counter=0x10)
2. **`secret`** → State 1→2 (contains "ret", counter=0x20) 
3. **`secret`** → State 2→3 (starts with 's', length>4, counter=0x120)
4. **`unlock`** → State 3→SUCCESS (exact match, REAL_TRIGGER=1)
5. **`secret`** → Get the flag!

### Counter Verification
- Initial: 0
- After state 0→1: 0 + 0x10 = 0x10
- After state 1→2: 0x10 × 2 = 0x20  
- After state 2→3: 0x20 + 0x100 = 0x120 ✅

## Flag Extraction

Since we cannot run the binary, we extract the flag using static analysis.

### String Analysis

Using the `strings` command to find embedded constants:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ strings modern_crackme1 | grep -E "[a-f0-9]{32}"
fbf02c4e1f041729b52fc049f83eca20}Access denied.GDBRUST_BACKTRACE...
```

The first match shows our MD5 hash: **`fbf02c4e1f041729b52fc049f83eca20`**

### Flag Construction

From the `real_hidden_function()` analysis, we know the flag format is constructed as:
- String "flag" 
- Formatted with the embedded MD5 hash
- Result: `flag{md5}`

## Final Solution

**Flag:** `flag{fbf02c4e1f041729b52fc049f83eca20}`

## Key Takeaways

1. **Static Analysis Mastery:** When dynamic analysis fails (cross-platform binaries), static analysis with tools like Ghidra is essential.

2. **Rust Binary Recognition:** The `std::rt::lang_start` pattern immediately identifies Rust binaries, which have different function naming conventions.

3. **State Machine Logic:** Understanding finite state machines is crucial for complex crackmes that require specific input sequences.

4. **String Extraction:** The `strings` command is invaluable for finding embedded constants when you can't execute the binary.

5. **Anti-Debug Awareness:** Modern crackmes often include anti-debug protections that complicate dynamic analysis.

## Tools Used

- **Ghidra:** Primary disassembly and reverse engineering
- **strings:** Static string extraction 
- **file:** Binary type identification
- **Static Analysis:** Complete solution without execution
