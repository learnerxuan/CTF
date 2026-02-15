---
ctf: VUWCTF 2025
category: rev
difficulty: easy
points: 100
flag: "VuwCTF{missing_function_is_data}"
techniques: [shellcode_analysis, mmap, xor_cipher]
tools: [objdump, python]
---

#Missing Function

## Description
A stripped ELF binary where the flag verification function is hidden as shellcode in the data section.

## Analysis

Running the binary prompts for a flag and validates it.

## Finding the Hidden Function

Disassembling the main function reveals it uses `mmap` to allocate executable memory. The program then copies data from the `.data` section into this executable region and calls it.

**The "missing function" is actually shellcode embedded in the data section!**

## Extracting the Shellcode

Dump the `.data` section to find the embedded code.

## Understanding the Algorithm

The verification function:
1. Checks that input length is exactly 29 bytes (0x1d)
2. Stores encrypted flag data on the stack using overlapping writes
3. Uses a 3-byte XOR key: `[0x83, 0xf1, 0xa0]`
4. For each character position, XORs the encrypted byte with `key[i % 3]` and compares to input

## Solution

### Disassembling the Verification Function

```nasm
   0:   push   %rbp
   1:   mov    %rsp,%rbp
   4:   mov    %rdi,-0x48(%rbp)      ; arg1: input string
   8:   mov    %esi,-0x4c(%rbp)      ; arg2: input length
   b:   cmpl   $0x1d,-0x4c(%rbp)     ; check length == 29
   f:   je     0x1b
  11:   mov    $0x0,%eax             ; return 0 if wrong length
  16:   jmp    0xc0

  ; Load encrypted flag data onto stack
  1b:   movabs $0x9ff8e6a5c0d784d5,%rax
  25:   movabs $0xecc29cfad3aeedcf,%rdx
  2f:   mov    %rax,-0x30(%rbp)
  33:   mov    %rdx,-0x28(%rbp)
  37:   movabs $0xc6aee0c99decc29c,%rax
  41:   movabs $0x8cedcf98f7c39ff6,%rdx
  4b:   mov    %rax,-0x23(%rbp)
  4f:   mov    %rdx,-0x1b(%rbp)

  ; Initialize loop counter and XOR key
  53:   movl   $0x0,-0x4(%rbp)       ; key_index = 0
  5a:   movw   $0xf183,-0x33(%rbp)   ; key[0..1] = 0x83, 0xf1
  60:   movb   $0xa0,-0x31(%rbp)     ; key[2] = 0xa0
  64:   movl   $0x0,-0x8(%rbp)       ; i = 0
  6b:   jmp    0xb5

  ; Main verification loop
  6d:   mov    -0x8(%rbp),%eax
  72:   movzbl -0x30(%rbp,%rax,1),%edx   ; encrypted[i]
  77:   mov    -0x4(%rbp),%eax
  7c:   movzbl -0x33(%rbp,%rax,1),%eax   ; key[key_index]
  81:   mov    %edx,%ecx
  83:   xor    %eax,%ecx                  ; decrypted = encrypted[i] ^ key[key_index]
  85:   mov    -0x8(%rbp),%eax
  8b:   mov    -0x48(%rbp),%rax
  8f:   add    %rdx,%rax
  92:   movzbl (%rax),%eax                ; input[i]
  95:   cmp    %al,%cl                    ; compare
  97:   je     0xa0
  99:   mov    $0x0,%eax                  ; return 0 on mismatch
  9e:   jmp    0xc0

  a0:   addl   $0x1,-0x4(%rbp)            ; key_index++
  a4:   cmpl   $0x3,-0x4(%rbp)            ; if key_index == 3
  a8:   jne    0xb1
  aa:   movl   $0x0,-0x4(%rbp)            ;   key_index = 0
  b1:   addl   $0x1,-0x8(%rbp)            ; i++
  b5:   cmpl   $0x1c,-0x8(%rbp)           ; while i <= 28
  b9:   jle    0x6d
  bb:   mov    $0x1,%eax                  ; return 1 (success)
  c0:   pop    %rbp
  c1:   ret
```

### Solver Script

```python
import struct

# Build the encrypted data array accounting for overlapping stack writes
data = bytearray(32)

# Store at -0x30 (offset 0)
data[0:8] = struct.pack('<Q', 0x9ff8e6a5c0d784d5)
# Store at -0x28 (offset 8)
data[8:16] = struct.pack('<Q', 0xecc29cfad3aeedcf)
# Store at -0x23 (offset 13) - overlapping!
data[13:21] = struct.pack('<Q', 0xc6aee0c99decc29c)
# Store at -0x1b (offset 21)
data[21:29] = struct.pack('<Q', 0x8cedcf98f7c39ff6)

# XOR key
key = bytes([0x83, 0xf1, 0xa0])

# Decrypt
flag = bytes([data[i] ^ key[i % 3] for i in range(29)])
print(flag.decode())
```

## Key Techniques
- Shellcode extraction from data section
- Dynamic code loading via mmap
- XOR cipher with 3-byte repeating key
- Length validation bypass
