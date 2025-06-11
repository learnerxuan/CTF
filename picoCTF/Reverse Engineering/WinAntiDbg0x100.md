# WinAntiDbg0x100 Reverse Engineering - Anti-Debugging Bypass Challenge

## Challenge Information

- **Platform:** Windows
- **File Type:** Windows PE Executable (.exe)
- **Architecture:** x86 (32-bit)
- **Difficulty:** Beginner to Intermediate
- **Skills Required:** Basic debugging, Anti-debugging bypass techniques

## Overview

This challenge involves bypassing an anti-debugging mechanism in a Windows executable to retrieve the flag. The program detects if it's running under a debugger and refuses to show the flag if debugging is detected.

## Initial Analysis

### Step 1: Download and Initial Execution

![Challenge file download](https://github.com/user-attachments/assets/105acb4e-3c7b-4dec-b3ea-8c04db591c7a)

First, download the provided `.exe` file and try running it normally:

![Initial execution attempt](https://github.com/user-attachments/assets/afc716ab-c6c4-4f8a-83a0-3679c8073167)

**Result:** The program indicates that it needs a debugger to run, which is our first hint about the challenge nature.

### Step 2: File Format Analysis

Before diving into debugging, let's analyze the file format using **Detect It Easy (DiE)**:

![File analysis with DiE](https://github.com/user-attachments/assets/2ffb76fc-c377-4831-8dcf-143fabef6ffb)

**Key Findings:**
- **Architecture:** x86 (32-bit)
- **File Format:** Windows PE Executable
- **Important:** We need to use x32dbg (not x64dbg) since this is a 32-bit executable

## Tools Required

### Essential Tools:
1. **x32dbg** - 32-bit debugger for Windows
2. **Ghidra** - Free reverse engineering tool by NSA
3. **Detect It Easy (DiE)** - File format analyzer

### Tool Installation:
- **x32dbg:** Download from [x64dbg.com](https://x64dbg.com/)
- **Ghidra:** Download from [NSA's GitHub](https://github.com/NationalSecurityAgency/ghidra)
- **DiE:** Download from [GitHub](https://github.com/horsicq/DIE-engine)

## Debugging Process

### Step 3: Loading the Program in x32dbg

1. **Open x32dbg**
2. **Load the executable:** File → Open → Select your .exe file
3. **Navigate to Debug menu**
4. **Select "Run to User Code"**

![x32dbg with Run to User Code](https://github.com/user-attachments/assets/e8741c5c-1eea-43f5-ac99-51d7b663990f)

#### What is "Run to User Code"?

**"Run to User Code"** is a debugger feature that automatically skips past:
- Operating system initialization code
- Library loading routines (DLLs)
- C runtime initialization
- Other boilerplate code

It stops execution at the **first line of actual program code** (like `main()` function), saving you from manually stepping through hundreds of irrelevant instructions.

### Step 4: Observing the Anti-Debugging Detection

After running to user code, check the **Log window** in x32dbg:

![Debugger detection message](https://github.com/user-attachments/assets/6ed51ca5-d53a-4924-8294-2936f1aa5891)

**Output:** 
```
DebugString: "### Oops! The debugger was detected. Try to bypass this check to get the flag!"
```

This confirms that the program has **anti-debugging protection** that detects our debugger and prevents flag extraction.

## Static Analysis with Ghidra

### Step 5: Analyzing the Source Code

1. **Open Ghidra**
2. **Create a new project**
3. **Import the .exe file**
4. **Let Ghidra analyze the binary** (accept default settings)
5. **Navigate to Symbol Tree → Functions**

![Ghidra function analysis](https://github.com/user-attachments/assets/f9b26a31-4c12-44de-829c-35255d66bd41)

Look for the function containing our detected message. In this case, it's **FUN_00401580**.

### Step 6: Understanding the Anti-Debugging Code

![IsDebuggerPresent function call](https://github.com/user-attachments/assets/80b5dfad-213d-4606-b9b7-0f4306ad146c)

**Key Code Analysis:**
```c
BVar3 = IsDebuggerPresent();
if (BVar3 == 0) {
    // Good path - show flag
    FUN_00401440(0xb);
    FUN_00401530(DAT_00405404);
    lpOutputString = FUN_004013b0(DAT_00405408);
    
    if (lpOutputString == (LPWSTR)0x0) {
        OutputDebugStringW(L"### Something went wrong...\n");
    } else {
        OutputDebugStringW(L"### Good job! Here's your flag:\n");
        OutputDebugStringW(L"### ~~~ ");
        OutputDebugStringW(lpOutputString); // <-- FLAG IS HERE!
        OutputDebugStringW(L"\n");
        free(lpOutputString);
    }
} else {
    // Bad path - debugger detected
    OutputDebugStringW(L"### Oops! The debugger was detected. Try to bypass this check to get the flag!\n");
}
```

#### Understanding IsDebuggerPresent()

**IsDebuggerPresent()** is a Windows API function that:
- **Returns 0** if no debugger is attached
- **Returns 1** if a debugger is detected
- **Purpose:** Anti-debugging protection mechanism

**The Logic:**
- If `IsDebuggerPresent() == 0` (no debugger) → Show flag
- If `IsDebuggerPresent() == 1` (debugger detected) → Show error message

## Assembly Analysis and Bypass Strategy

### Step 7: Finding the Critical Assembly Instructions

![Assembly code analysis](https://github.com/user-attachments/assets/8cf070f0-b252-4f1c-a0a3-936c085fbe3c)

**Critical Assembly Instructions:**
```assembly
00401602  85 C0    TEST EAX, EAX    ; Test if EAX is zero
00401604  74 15    JZ LAB_0040161b  ; Jump if Zero (to good path)
```

#### Understanding the Assembly:

1. **TEST EAX, EAX:**
   - Performs bitwise AND of EAX with itself
   - Sets Zero Flag (ZF) if EAX = 0
   - Clears Zero Flag (ZF) if EAX ≠ 0
   - **EAX contains the return value of IsDebuggerPresent()**

2. **JZ LAB_0040161b:**
   - **JZ = Jump if Zero**
   - Jumps to the "good path" if ZF is set (EAX was 0)
   - Continues to "bad path" if ZF is clear (EAX was 1)

### Step 8: The Bypass Strategy

**Goal:** Make the program think no debugger is present

**Method:** Change EAX from 1 to 0 right after `IsDebuggerPresent()` returns

**Why this works:**
- `IsDebuggerPresent()` returns 1 (debugger detected)
- We manually change EAX to 0 (no debugger)
- `TEST EAX, EAX` now sets Zero Flag
- `JZ` instruction jumps to the flag-printing code

## Practical Bypass Implementation

### Step 9: Setting Up the Bypass in x32dbg

1. **Return to x32dbg**
2. **Find address ending with 1602** (the TEST instruction)

![Setting breakpoint](https://github.com/user-attachments/assets/f0f84ffc-4a53-4a78-b8d1-d25a1164a957)

3. **Set a breakpoint:**
   - Click on address 00401602
   - Press **F2** (or right-click → Breakpoint → Toggle)
   - You should see a red dot indicating the breakpoint

### Step 10: Executing the Bypass

1. **Run the program:**
   - Press **F9** (Run)
   - Program will stop at our breakpoint

2. **Observe the registers:**
   - Look at the **Registers panel**
   - **EAX = 00000001** (debugger detected!)

![Register before modification](https://github.com/user-attachments/assets/f0f84ffc-4a53-4a78-b8d1-d25a1164a957)

3. **Modify EAX register:**
   - **Double-click on EAX** in the registers panel
   - **Change value from 1 to 0**
   - **Press Enter** to confirm

![Modifying EAX register](https://github.com/user-attachments/assets/10ab681c-4a0e-479e-abfe-7357f9c1e8f9)

4. **Continue execution:**
   - Press **F9** (Continue)
   - The program will now take the "good path"

### Step 11: Retrieving the Flag

Check the **Log window** in x32dbg:

![Flag revealed in log](https://github.com/user-attachments/assets/82685376-7c5a-42b6-9ac1-3319d57c8447)

**Success!** The flag is now displayed in the debug output.

## Learning Objectives

### What You've Learned:
1. **Anti-debugging techniques:** Understanding `IsDebuggerPresent()`
2. **Assembly analysis:** Reading x86 assembly instructions
3. **Dynamic analysis:** Using debuggers to modify program behavior
4. **Register manipulation:** Changing CPU registers during execution
5. **Windows PE analysis:** Understanding executable file structure
   

## Conclusion

This challenge demonstrates a fundamental anti-debugging technique used in both legitimate software protection and malware. By understanding how `IsDebuggerPresent()` works and learning to bypass it through register manipulation, you've gained valuable skills in:

- **Reverse Engineering**
- **Dynamic Analysis**
- **Assembly Language**
- **Debugging Techniques**

The key takeaway is that software protection mechanisms can often be bypassed with the right tools and knowledge, but this requires understanding both the high-level logic and low-level implementation details.

**Challenge completed successfully! 🚩**

