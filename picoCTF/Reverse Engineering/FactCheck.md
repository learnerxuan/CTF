# picoCTF FactCheck Challenge Writeup

## Challenge Information
- **Name:** FactCheck
- **Category:** Reverse Engineering
- **Description:** This binary is putting together some important piece of information... Can you uncover that information? Examine this file. Do you understand its inner workings?

## Table of Contents
1. [Initial Analysis](#initial-analysis)
2. [Static Analysis with Ghidra](#static-analysis-with-ghidra)
3. [Dynamic Analysis with GDB](#dynamic-analysis-with-gdb)
4. [Understanding the Flag Construction](#understanding-the-flag-construction)
5. [Solution](#solution)
6. [Key Concepts Learned](#key-concepts-learned)
7. [Tools Used](#tools-used)

## Initial Analysis

First, let's examine what type of file we're dealing with:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ file bin
bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ba87dd5805704ffe3d15a1e136c290a83fe95dba, 
for GNU/Linux 3.2.0, not stripped
```

### Key Observations:
- **ELF 64-bit**: Linux executable for 64-bit systems
- **PIE (Position Independent Executable)**: The binary will load at a random base address (ASLR)
- **Dynamically linked**: Uses shared libraries
- **Not stripped**: Function names and symbols are preserved (easier to reverse!)

## Static Analysis with Ghidra

### Loading the Binary
After loading the binary into Ghidra and analyzing it, I navigated to the `main` function. The decompiler showed an interesting pattern of string concatenation.

### Decompiled Code Analysis

```cpp
undefined8 main(void)
{
  char cVar1;
  char *pcVar2;
  long in_FS_OFFSET;
  
  // Multiple string allocations
  basic_string local_248 [32];  // This will hold our flag
  basic_string local_228 [32];
  basic_string local_208 [32];
  // ... many more local strings
  
  // Initialize base flag string
  std::__cxx11::basic_string<>::basic_string
            ((char *)local_248,(allocator *)"picoCTF{wELF_d0N3_mate_");
  
  // Initialize other string pieces from memory addresses
  std::__cxx11::basic_string<>::basic_string((char *)local_228,(allocator *)&DAT_0010201d);
  std::__cxx11::basic_string<>::basic_string((char *)local_208,(allocator *)&DAT_0010201f);
  // ... more string initializations
  
  // Conditional concatenations
  pcVar2 = (char *)std::__cxx11::basic_string<>::operator[]((ulong)local_208);
  if (*pcVar2 < 'B') {
    std::__cxx11::basic_string<>::operator+=(local_248,local_c8);
  }
  
  pcVar2 = (char *)std::__cxx11::basic_string<>::operator[]((ulong)local_a8);
  if (*pcVar2 != 'A') {
    std::__cxx11::basic_string<>::operator+=(local_248,local_68);
  }
  
  // Check if difference between characters equals 3
  pcVar2 = (char *)std::__cxx11::basic_string<>::operator[]((ulong)local_1c8);
  cVar1 = *pcVar2;
  pcVar2 = (char *)std::__cxx11::basic_string<>::operator[]((ulong)local_148);
  if ((int)cVar1 - (int)*pcVar2 == 3) {
    std::__cxx11::basic_string<>::operator+=(local_248,local_1c8);
  }
  
  // Unconditional concatenations
  std::__cxx11::basic_string<>::operator+=(local_248,local_1e8);
  std::__cxx11::basic_string<>::operator+=(local_248,local_188);
  
  // Check if character equals 'G'
  pcVar2 = (char *)std::__cxx11::basic_string<>::operator[]((ulong)local_168);
  if (*pcVar2 == 'G') {
    std::__cxx11::basic_string<>::operator+=(local_248,local_168);
  }
  
  // More unconditional concatenations
  std::__cxx11::basic_string<>::operator+=(local_248,local_1a8);
  std::__cxx11::basic_string<>::operator+=(local_248,local_88);
  std::__cxx11::basic_string<>::operator+=(local_248,local_228);
  std::__cxx11::basic_string<>::operator+=(local_248,local_128);
  
  // Add closing brace
  std::__cxx11::basic_string<>::operator+=(local_248,'}');
  
  // Cleanup (destructors)
  // ...
  return 0;
}
```

### Key Findings:
1. The program starts with `"picoCTF{wELF_d0N3_mate_"`
2. It loads various string pieces from data addresses (`DAT_0010201d`, etc.)
3. Some pieces are added conditionally based on character comparisons
4. Some pieces are always added
5. Finally, it adds the closing brace `'}'`

### Important Addresses in Ghidra:
- `main` function: `0x00101289`
- Last concatenation (adding '}'): `0x0010185b`
- After the last operation: `0x00101860` (MOV EBX, 0x0)

## Dynamic Analysis with GDB

Since we can't determine the actual string values from static analysis alone (they're stored at data addresses), we need to use dynamic analysis.

### Setting Up GDB with GEF

```bash
gdb ./bin
gef➤ break main
Breakpoint 1 at 0x1291
gef➤ run
```

### Understanding PIE and Address Translation

When the program runs, we see:
```
→ 0x555555555291 <main+0008>
```

This shows that:
- Static address in Ghidra: `0x00101291`
- Dynamic address in GDB: `0x555555555291`
- Base address: `0x555555555000`

**Address translation formula:**
```
Dynamic Address = Base Address + (Static Address - Image Base)
0x555555555291 = 0x555555555000 + (0x00101291 - 0x00101000)
```

### Setting the Strategic Breakpoint

I want to break right after all string operations are complete. Based on Ghidra analysis:
- Static address after last concatenation: `0x00101860`
- Calculate dynamic address: `0x555555555000 + 0x860 = 0x555555555860`

```bash
gef➤ break *0x555555555860
Breakpoint 2 at 0x555555555860
gef➤ continue
Continuing.
```

### Examining the Result

When the breakpoint hits, GEF shows us the stack contents:
<img width="997" height="447" alt="image" src="https://github.com/user-attachments/assets/4595ee3d-aa4c-4919-af9a-7601b100f5b8" />

## Understanding the Flag Construction

### Memory Layout

```
STACK (local_248 object):          HEAP (actual string data):
┌─────────────────────┐           ┌──────────────────────────────────┐
│ @ 0x7fffffffd980    │           │ @ 0x55555556b2d0                 │
│ pointer: 0x5556b2d0 │ ────────→ │ "picoCTF{wELF_d0N3_mate_e9da2c0e}"│
│ size: 32            │           └──────────────────────────────────┘
│ capacity: 32        │
└─────────────────────┘
```

### Why We See the Flag

1. **`local_248`** is a C++ string object on the stack
2. The string object contains a **pointer** to the heap where the actual characters are stored
3. **GEF automatically dereferenced** the pointer and showed us the string content
4. The registers `$rax` and `$rdi` also point here because they were just used in the `operator+=` function

## Solution

The flag is: **`picoCTF{wELF_d0N3_mate_e9da2c0e}`**

### Solution Approach Summary:
1. **Static Analysis**: Understand the program logic and identify where the flag is complete
2. **Calculate Breakpoint**: Convert static address to dynamic address accounting for PIE
3. **Dynamic Execution**: Run the program and break after flag construction
4. **Extract Flag**: Read the completed flag from memory

## Key Concepts Learned

### 1. PIE and ASLR
- Position Independent Executables load at random base addresses
- Must calculate runtime addresses: `runtime = base + (static - image_base)`

### 2. C++ String Implementation
- String objects on stack contain pointers to heap data
- The actual string characters are stored on the heap

### 3. Static vs Dynamic Analysis
- **Static**: Good for understanding program logic
- **Dynamic**: Necessary for seeing runtime values

### 4. GDB/GEF Usage
- Setting breakpoints at specific addresses
- Understanding stack layout
- Following pointers to see actual data

### 5. Reverse Engineering Workflow
```
1. File analysis (file command)
2. Static analysis (Ghidra/IDA)
3. Identify key operations
4. Dynamic analysis (GDB)
5. Extract the flag
```

## Tools Used

- **Ghidra**: Static analysis and decompilation
- **GDB with GEF**: Dynamic analysis and debugging
- **Linux file command**: Initial file identification

## Lessons for Future Challenges

1. **Always check file type first** - knowing it's PIE changes your approach
2. **Break AFTER operations complete** - not during function calls
3. **Trust register hints** - GEF shows which registers point to important data
4. **Combine static and dynamic analysis** - neither alone gives the complete picture
5. **Understand memory layout** - stack vs heap, and how C++ objects work
