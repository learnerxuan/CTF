# apuBOT - CTF Reverse Engineering Writeup

## Challenge Information

**Challenge Name:** apuBOT  
**Points:** 200  
**Difficulty:** Medium  
**Category:** Reverse Engineering  
**Author:** @pancakess  
**Flag Format:** `CYNX{r3ad4bl3_Ch@r4c7eR5}`

### Description
> I have entrusted apuBOT with my secret flag! Hopefully, apuBOT knows how to defend against pesky hackers!

### Hints
- **Hint #1:** Solution doesn't require analysis beyond main.
- **Hint #2:** What function is still readable in main?

---

## Initial Analysis

Let's start by examining the provided binary:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ file apuBOT    
apuBOT: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), statically linked, no section header
```

The binary appears to be a 64-bit ELF executable, but let's check if it's packed:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ strings apuBOT | head -20
UPX!
-@xa
tdoP7
-oQ7
/lib64
nux-x86-
so.2
...
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
```

The strings output shows clear indicators that this binary is **UPX packed**. We can see the UPX signature and copyright information at the end of the strings output.

## Unpacking the Binary

Since the binary is UPX packed, we need to unpack it to perform proper analysis:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ upx -d apuBOT -o original
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2024
UPX 4.2.4       Markus Oberhumer, Laszlo Molnar & John Reiser    May 9th 2024

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     46147 <-     22684   49.16%   linux/amd64   original

Unpacked 1 file.
```

Success! The file has been unpacked from 22,684 bytes to 46,147 bytes. Now let's examine the unpacked binary:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ file original
original: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, not stripped
```

Much better! Now we have a standard ELF binary that's not stripped.

## Static Analysis

Let's examine the strings in the unpacked binary:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ strings original | grep -E "(password|APU|flag|access)"
> password: 
           APU BOT v1.0  
Feed me today's access password to proceed.
Access granted. apuBOT Trusts U WITH ThA Flag ( 
Access denied. apuBOT suggests: try again later :)
gen_password
```

Key observations:
1. The bot asks for "today's access password"
2. There's a function called `gen_password` 
3. The password appears to be time-based ("today's")

Let's run the binary to see its behavior:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ chmod +x original && ./original
╭────────────────────────────────────╮
│           APU BOT v1.0  🤖         │
╰────────────────────────────────────╯
Greetings, human. I am *apuBOT*.
Feed me today's access password to proceed.

> password: test
❌ Access denied. apuBOT suggests: try again later :)
```

The bot requires a specific password. Given that it mentions "today's password" and there's a `gen_password` function, this suggests the password is dynamically generated.

## Finding the Key Function

Based on **Hint #2** ("What function is still readable in main?"), let's examine the main function using objdump:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ objdump -d original | grep -A 50 "gen_password"
    11ce:	e8 ed 0c 00 00       	call   1ec0 <gen_password>
    11d3:	48 8d 3d 46 0e 00 00 	lea    0xe46(%rip),%rdi        # 2020 <_IO_stdin_used+0x20>
    11da:	e8 61 fe ff ff       	call   1040 <puts@plt>
    11df:	48 8d 3d 2d 0e 00 00 	lea    0xe2d(%rip),%rdi        # 2013 <_IO_stdin_used+0x13>
```

Let's look at the complete `gen_password` function:

```assembly
0000000000001ec0 <gen_password>:
    1ec0:	55                   	push   %rbp
    1ec1:	48 89 e5             	mov    %rsp,%rbp
    1ec4:	41 57                	push   %r15
    1ec6:	4c 8d 3d d3 03 00 00 	lea    0x3d3(%rip),%r15        # 22a0 <ALNUM.1>
    1ecd:	41 56                	push   %r14
    1ecf:	49 89 fe             	mov    %rdi,%r14    # Store buffer address
    1ed2:	41 55                	push   %r13
    1ed4:	49 89 fd             	mov    %rdi,%r13    # Store buffer address again
    1ed7:	41 54                	push   %r12
    1ed9:	4c 8d 67 10          	lea    0x10(%rdi),%r12  # buffer + 16 bytes
    1edd:	53                   	push   %rbx
    1ede:	48 bb 09 21 84 10 42 	movabs $0x8421084210842109,%rbx
    1ee5:	08 21 84 
    1ee8:	48 83 ec 08          	sub    $0x8,%rsp
    1eec:	0f 1f 40 00          	nopl   0x0(%rax)
    1ef0:	e8 3b f2 ff ff       	call   1130 <rand@plt>    # Generate random number
    1ef5:	49 83 c6 01          	add    $0x1,%r14
    1ef9:	48 63 c8             	movslq %eax,%rcx
    1efc:	48 89 ca             	mov    %rcx,%rdx
    1eff:	48 d1 ea             	shr    $1,%rdx
    1f02:	48 89 d0             	mov    %rdx,%rax
    1f05:	48 f7 e3             	mul    %rbx
    1f08:	48 c1 ea 04          	shr    $0x4,%rdx
    1f0c:	48 89 d0             	mov    %rdx,%rax
    1f0f:	48 c1 e0 05          	shl    $0x5,%rax
    1f13:	48 29 d0             	sub    %rdx,%rax
    1f16:	48 01 c0             	add    %rax,%rax
    1f19:	48 29 c1             	sub    %rax,%rcx
    1f1c:	41 0f b6 04 0f       	movzbl (%r15,%rcx,1),%eax  # Index into ALNUM array
    1f21:	41 88 46 ff          	mov    %al,-0x1(%r14)      # Store character
    1f25:	4d 39 e6             	cmp    %r12,%r14
    1f28:	75 c6                	jne    1ef0 <gen_password+0x30>  # Loop until 16 chars
    1f2a:	41 c6 45 10 00       	movb   $0x0,0x10(%r13)     # Null terminate
    1f2f:	48 83 c4 08          	add    $0x8,%rsp
    1f33:	5b                   	pop    %rbx
    1f34:	41 5c                	pop    %r12
    1f36:	41 5d                	pop    %r13
    1f38:	41 5e                	pop    %r14
    1f3a:	41 5f                	pop    %r15
    1f3c:	5d                   	pop    %rbp
    1f3d:	c3                   	ret
```

## Analysis of gen_password

The `gen_password` function:
1. Takes a buffer pointer as argument (`%rdi`)
2. Uses `rand()` to generate random numbers
3. Uses modular arithmetic to index into an ALNUM character set (0-9, A-Z, a-z)
4. Generates a 16-character password
5. Null-terminates the string

The key insight is that this uses `rand()`, which means the seed matters. Let's examine how `srand()` is called in main:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ objdump -d original | grep -B5 -A5 srand
    11b6:	e8 95 fe ff ff       	call   1050 <clock@plt>
    11bb:	89 df                	mov    %ebx,%edi
    11bd:	48 8d 9d d0 fe ff ff 	lea    -0x130(%rbp),%rbx
    11c4:	31 c7                	xor    %eax,%edi
    11c6:	e8 e5 fe ff ff       	call   10b0 <srand@plt>
    11cb:	4c 89 e7             	mov    %r12,%rdi
    11ce:	e8 ed 0c 00 00       	call   1ec0 <gen_password>
```

The seeding mechanism is:
1. Call `time()` (stored in `%rbx`)
2. Call `clock()` (result in `%rax`)
3. XOR them together: `seed = time() XOR clock()`
4. Call `srand(seed)`

## Dynamic Analysis with GDB

Since we know the password is generated using `gen_password`, let's use GDB to extract it. First, let's examine the main function to find the right breakpoint:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ gdb ./original
gef➤ break main
gef➤ run
gef➤ disas main
```

Looking at the disassembly, we can see `gen_password` is called at address `+78` (0x5555555551ce), and the next instruction is at `+83` (0x5555555551d3).

Let's set a breakpoint right after `gen_password` finishes:

```bash
gef➤ break *0x5555555551d3
gef➤ continue
```

**Critical Insight:** We need to let the program run normally so that it properly seeds the random number generator with its `time() XOR clock()` mechanism, rather than calling `gen_password` directly.

When the breakpoint hits, we can examine the generated password:

```bash
gef➤ x/s $r12
0x7fffffffda40:	"PUkRljMgcgmeJXKq"
```

Perfect! The generated password is: **`PUkRljMgcgmeJXKq`**

## Solution Verification

Now let's test this password:

```bash
gef➤ continue
Continuing.
╭────────────────────────────────────╮
│           APU BOT v1.0  🤖         │
╰────────────────────────────────────╯
Greetings, human. I am *apuBOT*.
Feed me today's access password to proceed.
> password: PUkRljMgcgmeJXKq
✅ Access granted. apuBOT Trusts U WITH ThA Flag ( ಥـْـِـِـِـْಥ)🤜 🤛(ಥـْـِـِـِـْಥ)
Q1lOWHtOM3ZlUl83cnVzVF9AX0NsQG5LM1IhfQ==
```

Success! We received a Base64-encoded string. Let's decode it:

```bash
┌──(xuan㉿kali)-[~/random]
└─$ echo "Q1lOWHtOM3ZlUl83cnVzVF9AX0NsQG5LM1IhfQ==" | base64 -d
CYNX{N3veR_7rusT_@_Cl@nK3R!}
```

## Flag

**`CYNX{N3veR_7rusT_@_Cl@nK3R!}`**

## Key Lessons Learned

1. **UPX Unpacking:** Always check for packed binaries using tools like `strings` and `file`. UPX is a common packer that can be easily unpacked with the `upx -d` command.

2. **Hint Interpretation:** The hints were crucial:
   - "Solution doesn't require analysis beyond main" → Focus on main function
   - "What function is still readable in main?" → The `gen_password` function was the key

3. **Dynamic Analysis Over Static:** While we could have reverse engineered the entire password generation algorithm, using GDB to extract the password as it's generated was much more efficient.

4. **Seeding Matters:** The program used a specific seeding mechanism (`time() XOR clock()`), which is why calling `gen_password` directly wouldn't work—we needed to let the program initialize its own seed.

5. **Time-based Passwords:** The phrase "today's access password" was a hint that the password changes based on time, making it necessary to extract it dynamically rather than through static analysis.

## Alternative Approaches

1. **Full Reverse Engineering:** We could have completely reversed the seeding algorithm and password generation to compute the password mathematically.

2. **Memory Patching:** We could have patched the binary to always accept any password.

3. **Return Address Manipulation:** We could have manipulated the program flow to skip the password check entirely.

However, the dynamic analysis approach using GDB was the most straightforward and aligned perfectly with the challenge hints.

## Technical Details

- **Binary Type:** ELF 64-bit, dynamically linked
- **Packer:** UPX 4.24
- **Architecture:** x86-64
- **Key Function:** `gen_password` - generates 16-character alphanumeric password
- **Seeding:** `srand(time() ^ clock())`
- **Character Set:** 0-9, A-Z, a-z (62 characters total)

The challenge name "apuBOT" and flag message "Never trust a clanker!" appear to be Star Wars references, where "clankers" was slang for battle droids. The lesson is about not trusting automated security systems and finding ways to understand and bypass their mechanisms.
