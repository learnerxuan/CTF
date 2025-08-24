# ASCII FTW - Reverse Engineering Challenge Writeup

## Challenge Information
- **Challenge Name:** ASCII FTW (asciiftw)
- **Category:** Reverse Engineering
- **Difficulty:** Beginner

## Challenge Description
We're given a binary file called `asciiftw` with minimal description. The goal is to find the hidden flag within the executable.

## Initial Analysis

### File Information
Let's start by examining what type of file we're dealing with:

```bash
$ file asciiftw 
asciiftw: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c29491782ee13aa7c5734d77b281865b608e46e9, for GNU/Linux 3.2.0, not stripped
```

Key observations:
- 64-bit ELF executable
- PIE (Position Independent Executable) enabled
- Not stripped (symbols are present)
- Dynamically linked

### Security Protections
```bash
$ checksec --file=asciiftw 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   66 Symbols	  No	0		1		asciiftw
```

The binary has several security protections enabled:
- **Full RELRO**: Read-only relocations
- **Stack Canary**: Stack overflow protection
- **NX enabled**: Non-executable stack
- **PIE enabled**: Address Space Layout Randomization

### Running the Binary
```bash
$ chmod +x asciiftw
$ ./asciiftw 
The flag starts with 70
```

The program gives us a hint: "The flag starts with 70". This is likely a hexadecimal value (0x70) or decimal value (70).

## Static Analysis

Since the program only gives us a partial hint, let's analyze the assembly code to find the complete flag.

### Disassembling the Main Function

Using `objdump -d asciiftw`, we can examine the main function starting at address `0x1169`:

```assembly
0000000000001169 <main>:
    1169:	f3 0f 1e fa          	endbr64
    116d:	55                   	push   %rbp
    116e:	48 89 e5             	mov    %rsp,%rbp
    1171:	48 83 ec 30          	sub    $0x30,%rsp     ; Allocate 48 bytes on stack
    1175:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax  ; Stack canary
    117c:	00 00 
    117e:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
    1182:	31 c0                	xor    %eax,%eax
```

The function sets up the stack frame and implements stack canary protection. The interesting part starts at address `0x1184`:

### Flag Construction

The program systematically builds a string on the stack using individual byte moves:

```assembly
    1184:	c6 45 d0 70          	movb   $0x70,-0x30(%rbp)  ; 'p'
    1188:	c6 45 d1 69          	movb   $0x69,-0x2f(%rbp)  ; 'i'
    118c:	c6 45 d2 63          	movb   $0x63,-0x2e(%rbp)  ; 'c'
    1190:	c6 45 d3 6f          	movb   $0x6f,-0x2d(%rbp)  ; 'o'
    1194:	c6 45 d4 43          	movb   $0x43,-0x2c(%rbp)  ; 'C'
    1198:	c6 45 d5 54          	movb   $0x54,-0x2b(%rbp)  ; 'T'
    119c:	c6 45 d6 46          	movb   $0x46,-0x2a(%rbp)  ; 'F'
    11a0:	c6 45 d7 7b          	movb   $0x7b,-0x29(%rbp)  ; '{'
    11a4:	c6 45 d8 41          	movb   $0x41,-0x28(%rbp)  ; 'A'
    11a8:	c6 45 d9 53          	movb   $0x53,-0x27(%rbp)  ; 'S'
    11ac:	c6 45 da 43          	movb   $0x43,-0x26(%rbp)  ; 'C'
    11b0:	c6 45 db 49          	movb   $0x49,-0x25(%rbp)  ; 'I'
    11b4:	c6 45 dc 49          	movb   $0x49,-0x24(%rbp)  ; 'I'
    11b8:	c6 45 dd 5f          	movb   $0x5f,-0x23(%rbp)  ; '_'
    11bc:	c6 45 de 49          	movb   $0x49,-0x22(%rbp)  ; 'I'
    11c0:	c6 45 df 53          	movb   $0x53,-0x21(%rbp)  ; 'S'
    11c4:	c6 45 e0 5f          	movb   $0x5f,-0x20(%rbp)  ; '_'
    11c8:	c6 45 e1 45          	movb   $0x45,-0x1f(%rbp)  ; 'E'
    11cc:	c6 45 e2 41          	movb   $0x41,-0x1e(%rbp)  ; 'A'
    11d0:	c6 45 e3 53          	movb   $0x53,-0x1d(%rbp)  ; 'S'
    11d4:	c6 45 e4 59          	movb   $0x59,-0x1c(%rbp)  ; 'Y'
    11d8:	c6 45 e5 5f          	movb   $0x5f,-0x1b(%rbp)  ; '_'
    11dc:	c6 45 e6 33          	movb   $0x33,-0x1a(%rbp)  ; '3'
    11e0:	c6 45 e7 43          	movb   $0x43,-0x19(%rbp)  ; 'C'
    11e4:	c6 45 e8 46          	movb   $0x46,-0x18(%rbp)  ; 'F'
    11e8:	c6 45 e9 34          	movb   $0x34,-0x17(%rbp)  ; '4'
    11ec:	c6 45 ea 42          	movb   $0x42,-0x16(%rbp)  ; 'B'
    11f0:	c6 45 eb 46          	movb   $0x46,-0x15(%rbp)  ; 'F'
    11f4:	c6 45 ec 41          	movb   $0x41,-0x14(%rbp)  ; 'A'
    11f8:	c6 45 ed 44          	movb   $0x44,-0x13(%rbp)  ; 'D'
    11fc:	c6 45 ee 7d          	movb   $0x7d,-0x12(%rbp)  ; '}'
```

### Program Output Logic

After building the string, the program only prints the first character:

```assembly
    1200:	0f b6 45 d0          	movzbl -0x30(%rbp),%eax   ; Load first byte
    1204:	0f be c0             	movsbl %al,%eax           ; Sign extend to int
    1207:	89 c6                	mov    %eax,%esi          ; Move to second argument
    1209:	48 8d 3d f4 0d 00 00 	lea    0xdf4(%rip),%rdi   ; Load format string
    1210:	b8 00 00 00 00       	mov    $0x0,%eax
    1215:	e8 56 fe ff ff       	call   1070 <printf@plt>  ; Call printf
```

The program loads only the first character at offset `-0x30(%rbp)` and prints it with the message "The flag starts with [character]".

## Flag Extraction

### Converting Hex to ASCII

Let's extract all the hex values and convert them to ASCII characters:

```python
hex_values = [
    0x70, 0x69, 0x63, 0x6f, 0x43, 0x54, 0x46, 0x7b,  # "picoCTF{"
    0x41, 0x53, 0x43, 0x49, 0x49, 0x5f, 0x49, 0x53,  # "ASCII_IS"
    0x5f, 0x45, 0x41, 0x53, 0x59, 0x5f, 0x33, 0x43,  # "_EASY_3C"
    0x46, 0x34, 0x42, 0x46, 0x41, 0x44, 0x7d          # "F4BFAD}"
]

flag = ''.join(chr(hex_val) for hex_val in hex_values)
print(f"Flag: {flag}")
```

## Solution

**Flag:** `picoCTF{ASCII_IS_EASY_3CF4BFAD}`


- **Stack frame analysis** - understanding rbp offsets helps locate local variables
- **Function calling conventions** - knowing how parameters are passed helps understand program flow

This challenge serves as an excellent introduction to reverse engineering, teaching fundamental concepts while remaining accessible to beginners.
