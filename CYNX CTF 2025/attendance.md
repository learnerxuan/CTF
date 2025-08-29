# Attendance Challenge - Reverse Engineering CTF Writeup

## Challenge Information

**Challenge Name:** Attendance  
**Category:** Reverse Engineering  
**Flag Format:** CYNX{r3ad4bl3_Ch@r4c7eR5}  
**Hint:** Hope you can read assembly ;)

**Challenge Description:**
> I asked my friend to make me an attendance system for my class. One day, I inserted the number 3, and some strange text appeared.

## Initial Analysis

### File Examination

```bash
$ file attendance
attendance: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

The binary is a 64-bit Linux executable that's statically linked and not stripped, which means we'll have symbol information available.

### Running the Program

```bash
$ ./attendance

Menu:
1. Mark Attendance
2. View Attendance
3. Exit Program

Enter a number: 1
Which students are present (1 - 10) | If finished input 'done': 
3
Which students are present (1 - 10) | If finished input 'done': 
done

Menu:
1. Mark Attendance
2. View Attendance
3. Exit Program

Enter a number: 2
Student 1: Absent
Student 2: Absent
Student 3: Present
Student 4: Absent
Student 5: Absent
Student 6: Absent
Student 7: Absent
Student 8: Absent
Student 9: Absent
Student 10: Absent
```

The program appears to be a simple attendance system with basic functionality. The challenge mentions that inputting "3" produces "strange text," but our initial testing doesn't reveal anything unusual.

## Static Analysis

### String Analysis

```bash
$ strings attendance | head -20
attendance.txt
Menu:
1. Mark Attendance
2. View Attendance
3. Exit Program
Error opening file
Input 1 is printing!
Input 2 is printing!
Invalid Input. Try again :)
Enter a number: 
Student 
Present
Absent
Calling functions directly is STRICTLY forbidden in this class!
Getting the flag shouldn't be that easy
```

Several interesting strings stand out:
- "Calling functions directly is STRICTLY forbidden in this class!"
- "Getting the flag shouldn't be that easy"

These suggest hidden functionality beyond the basic attendance system.

### Function Analysis

```bash
$ objdump -t attendance | grep -E "(relay|Flag|Key)"
0000000000401324 g     F .text	000000000000003b relay_1
0000000000401359 g     F .text	000000000000003b relay_2
...
0000000000401e9f g     F .text	000000000000003b relay_50
0000000000401300 g     F .text	0000000000000024 getFlagKey
00000000004012dc g     F .text	0000000000000024 printFlag
```

The binary contains 50 relay functions (`relay_1` through `relay_50`), plus `printFlag` and `getFlagKey` functions. This suggests a complex decryption mechanism.

### Disassembly Analysis

Looking at the main loop logic:

```assembly
main_loop.handle_2:
  ; ... attendance viewing logic ...
  
main_loop.next_char:
  mov    (%r8),%al          ; Read character from attendance data
  cmp    $0x0,%al           ; Check for null terminator
  je     401005 <main_loop>
  ; ... processing logic ...
  
main_loop.load_data:
  mov    $0x26,%ecx         ; ECX = 38 (0x26)
  mov    %ecx,%eax          ; EAX = 38
  mov    $0x0,%edx          ; EDX = 0
  mov    $0x34,%ebx         ; EBX = 52
  div    %ebx               ; EAX = 38/52 = 0, EDX = 38%52 = 38
  ; ...
  jmp    *0x4032b4(,%rcx,8) ; Computed jump using ECX as index
```

The critical discovery: when viewing attendance, if a character is neither '1' (present) nor '0' (absent), it jumps to `load_data`, which performs a computed jump to one of the relay functions.

### Jump Table Analysis

```bash
$ objdump -s -j .data attendance | grep -A 10 4032b4
4032b0 00000000 dc124000 00000000 00134000  ......@.......@.
4032c0 00000000 24134000 00000000 5f134000  ....$.@....._.@.
```

Converting these little-endian addresses:
- **Index 0:** 0x004012dc → `printFlag` function
- **Index 1:** 0x00401324 → `relay_1`
- **Index 2:** 0x0040135f → `relay_2`
- **Index 3:** 0x0040139a → `relay_3`

The jump table's first entry points directly to `printFlag`! If we could make ECX=0 before the jump, we'd get the flag immediately.

## Dynamic Analysis with GDB

### Setting Up Debugging

```bash
$ gdb ./attendance
(gdb) set disassembly-flavor intel
(gdb) info functions | grep present
0x000000000040212b  input_loop.present_1
0x0000000000402138  input_loop.present_2
0x0000000000402145  input_loop.present_3
0x0000000000402152  input_loop.present_three  # <- Interesting!
0x000000000040215f  input_loop.present_4
```

Notice there are two functions for "3": `present_3` and `present_three`. This suggests different handling for different representations of "3".

### Examining String Comparisons

```bash
(gdb) break *0x401f88  # String comparison in input loop
(gdb) run
# Choose option 1, enter "3" as student input
# Hit breakpoint...

(gdb) x/20s 0x403540
0x403540:	"again :)\n1"
0x40354b:	"2"
0x40354d:	"3"
0x40354f:	"4"
0x403551:	"5"
0x403553:	"6"
0x403555:	"7"
0x403557:	"8"
0x403559:	"9"
0x40355b:	"10"
0x40355e:	"done"
0x403563:	"３"          # <- Unicode full-width "3"!
```

The crucial discovery: at address `0x403563` is the Unicode character "３" (U+FF13), which is a full-width "3" that looks identical to regular "3" but is technically different.

### Function Behavior Analysis

```assembly
present_3:
  mov    BYTE PTR ds:0x403495, 0x1    ; Store 1 (present)
  jmp    0x401f0d

present_three:  
  mov    BYTE PTR ds:0x403495, 0x3    ; Store 3 (special value!)
  jmp    0x401f0d
```

The key difference:
- Regular "3" → `present_3` → stores value `1`
- Unicode "３" → `present_three` → stores value `3`

### Testing the Theory

```bash
(gdb) break *0x402152  # Break at present_three
(gdb) run
# Choose option 1
# Enter Unicode "３" character
# Breakpoint hits!
```

When viewing attendance after marking with Unicode "３":

```
Student 3: CYNX{H1dd3n_Num3_Hom0glyph}
```

## Solution Mechanism

### The Attack Chain

1. **Input Unicode homoglyph:** Enter "３" (U+FF13) instead of "3" (U+0033)
2. **Trigger special handler:** This calls `present_three` instead of `present_3`
3. **Store special value:** The attendance data contains `3` instead of `1`
4. **Trigger decryption:** When viewing attendance, the `3` character triggers `load_data`
5. **Execute relay function:** The computed jump leads to a relay function that decrypts the flag

### Why This Works

The attendance viewing logic expects only '1' (present) or '0' (absent):

```assembly
mov    (%r8),%al          ; Read attendance character
cmp    $0x31,%al          ; Compare with '1'
je     present_handler
cmp    $0x30,%al          ; Compare with '0'  
je     absent_handler
jmp    load_data          ; ANY OTHER CHARACTER -> load_data
```

By storing the value `3` (ASCII 0x33) in the attendance data, we bypass the normal handlers and trigger the hidden decryption mechanism.

## Relay Function Analysis

The relay functions perform XOR decryption on encrypted flag data:

```assembly
relay_1.relay1.1:
  mov    0x403238(%rsi),%al    ; Load encrypted byte
  xor    0x4031db(%rsi),%al    ; XOR with key
  mov    %al,0x403295(%rsi)    ; Store decrypted byte
  inc    %rsi
  loop   40132c               ; Repeat for all bytes
  ; Print decrypted data
```

Each relay function uses different XOR keys and data sources, presumably to decrypt different parts of the flag or create a decryption chain.

## The Complete Solution

### Step-by-Step

1. Run the attendance program
2. Choose option 1 (Mark Attendance)
3. Enter the Unicode character "３" (full-width 3, U+FF13)
4. Enter "done" to finish attendance marking
5. Choose option 2 (View Attendance)
6. The flag appears: `CYNX{H1dd3n_Num3_Hom0glyph}`

### Inputting Unicode Characters

You can input the Unicode character in several ways:
- Copy/paste: "３"
- Linux: `Ctrl+Shift+U`, type `FF13`, press Enter
- Character map/picker applications

## Key Insights and Techniques

### Homoglyph Attack

The challenge demonstrates a **homoglyph attack** - using visually identical but technically different Unicode characters to bypass input validation or trigger hidden functionality. This is a real security concern in applications that don't properly handle Unicode normalization.

### Reverse Engineering Methodology

This challenge showcased several important RE techniques:

1. **Static Analysis:** Identifying unusual functions and string patterns
2. **Dynamic Analysis:** Using GDB to trace execution and examine memory
3. **Control Flow Analysis:** Understanding computed jumps and jump tables
4. **Character Set Analysis:** Recognizing Unicode vs ASCII differences
5. **Pattern Recognition:** Connecting function names to their purposes

### Assembly Reading Skills

The challenge required understanding:
- x86-64 assembly syntax and instructions
- System calls and calling conventions  
- Memory addressing modes
- Conditional jumps and computed jumps
- XOR encryption/decryption patterns

## Conclusion

The "Attendance" challenge was a sophisticated reverse engineering puzzle that combined multiple techniques:

- **Static analysis** to discover the relay functions and jump table
- **Dynamic debugging** to trace execution flow
- **Unicode knowledge** to identify the homoglyph trigger
- **Assembly analysis** to understand the decryption mechanism

The flag name `H1dd3n_Num3_Hom0glyph` perfectly describes the solution technique - using a hidden Unicode homoglyph of the number 3 to trigger flag decryption.

This challenge effectively demonstrates why thorough binary analysis, systematic debugging, and attention to character encoding details are essential skills for reverse engineering complex programs.

**Flag:** `CYNX{H1dd3n_Num3_Hom0glyph}`
