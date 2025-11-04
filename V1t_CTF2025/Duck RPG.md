# Duck RPG CTF Challenge - Complete Explanation

## Challenge Overview
This is a reverse engineering challenge where you need to find a "secret ending" in a batch file game to get the flag.

---

## Part 1: Understanding game.bat

### The Normal Game Flow

```
Start → battle1 → battle2 → battle3 → victory → result.bat
```

#### 1. Main Menu (:mainmenu)
```batch
:mainmenu
echo 1. Start Adventure
echo 2. Quit
set /p choice=Choose: 
if "%choice%"=="1" goto intro
```
- Shows a menu
- `set /p` = prompt user for input
- `goto intro` = jump to the `:intro` label

#### 2. Introduction (:intro)
```batch
:intro
echo In a world overrun by evil ducks...
set /a hero_hp=100    # Set hero HP to 100
goto battle1           # Start first battle
```

#### 3. Battle Sequence

**Battle 1 - Angry Duck**
```batch
:battle1
call :fight "Angry Duck" 50 8    # Call fight function with parameters
if "!hero_dead!"=="1" goto gameover
set "frag1=unlock"                # Set first fragment: "unlock"
goto battle2
```

**Battle 2 - Duck Mage**
```batch
:battle2
call :fight "Duck Mage" 100 12
if "!hero_dead!"=="1" goto gameover
set "frag2=the"                   # Set second fragment: "the"
goto battle3                       # ← KEY LINE: Goes to battle3
```

**Battle 3 - Mother Goose**
```batch
:battle3
call :fight "Mother Goose" 420 69  # Very strong boss!
if "!hero_dead!"=="1" goto gameover
set "frag3=goose"                  # Set third fragment: "goose"
goto victory
```

**THE HIDDEN Battle 0 - Tiny Duck** (at the bottom of file)
```batch
:battle0                           # ← THIS IS NEVER REACHED NORMALLY!
call :fight "Tiny Duck" 1 1        # Super weak enemy (1 HP, 1 attack)
if "!hero_dead!"=="1" goto gameover
set "frag3=duck"                   # ← DIFFERENT fragment: "duck" not "goose"!
goto victory
```

#### 4. Victory Screen
```batch
:victory
set "full=%frag1%%frag2%%frag3%"   # Combine fragments
# Normal path: unlock + the + goose = "unlockthegoose"
# Secret path: unlock + the + duck  = "unlocktheduck"

set "self=%~f0"                     # Get full path of current batch file
set "hash="
# Calculate SHA256 hash of the batch file itself
for /f "skip=1 tokens=1" %%H in ('certutil -hashfile "%self%" SHA256') do (
    call set "hash=%%H"
    goto result
)

:result
call result.bat !full! !hash!      # Call result.bat with password and hash
```

**What happens:**
- Normal game: `result.bat unlockthegoose <hash>`
- Secret game: `result.bat unlocktheduck <hash>`

---

## Part 2: Understanding result.bat (Obfuscated)

### The Obfuscation Technique

result.bat uses **variable substring extraction** to hide strings:

```batch
set "�Bc�=@1lYWZUrksK9Mwxd2PLGypH68fOStF4Abaq3zXDeuJNRc Bo7h0gvni5IjmCTQVE"
```

This creates a variable containing 64 characters. Then it extracts characters by position:

```batch
%�Bc�:~0,1%    # Extract 1 character starting at position 0 → '@'
%�Bc�:~1,1%    # Extract 1 character starting at position 1 → '1'
%�Bc�:~28,1%   # Extract 1 character starting at position 28 → 't'
```

### Decoded Structure of result.bat

```batch
@echo off
@cls
set "chars=@1lYWZUrksK9Mwxd2PLGypH68fOStF4Abaq3zXDeuJNRc Bo7h0gvni5IjmCTQVE"

# Check 1: If no argument provided
if "%~1"=="" (
    echo Error / Usage
    exit /b
)

# Check 2: Verify file integrity (anti-tamper protection)
if "%~2"=="8392dcc7b6fdebd5a70211c1e21497a553b31f2c70408b772c4a313615df7b60" (
    echo File hash verified (but doesn't show anything yet)
    exit /b
)

# Check 3: SECRET FLAG - if password is "unlocktheduck"
if "%~1"=="unlocktheduck" (
    echo v1t{p4tch_th3_b4tch_t0_g3t_th3_s3cr3t_3nd1ng}
)
else (
    exit /b
)

# Check 4: Normal ending - if password is "unlockthegoose"
if "%~1"=="unlockthegoose" (
    echo Good job! You beat the game the normal way!
)
else (
    exit /b
)
```

### How the Flag is Hidden

The flag characters are extracted from positions in the character array:
```
Position:  0   1   28  21  30  28  44  49  ...
Character: @   1   t   {   p   t   4   c   ...
           
Result: v1t{p4tch_th3_b4tch_t0_g3t_th3_s3cr3t_3nd1ng}
```

---

## The Security Mechanism: SHA256 Hash Check

### What is it?
The game calculates its **own hash** when it runs:
```batch
certutil -hashfile "%self%" SHA256
```

This produces: `8392dcc7b6fdebd5a70211c1e21497a553b31f2c70408b772c4a313615df7b60`

### Why it matters:
If you modify `game.bat`, the hash changes, and `result.bat` detects the tampering!

```
Original game.bat → Hash: 8392dcc7b6f...
Modified game.bat → Hash: 1234567890a... (different!)
                    ↓
             result.bat says: "Nuh uh you can not change the game code"
```

---

## The Solution Path

### Why You Can't Patch game.bat Directly

```batch
# If you change this:
goto battle3
# To this:
goto battle0

# The file contents change → SHA256 hash changes → result.bat rejects it!
```

### The Actual Solution: Static Analysis

Instead of playing the game, you **reverse engineer** the obfuscated result.bat:

1. **Identify the character array**: The 64-character string
2. **Map the substring extractions**: Track which positions spell the flag
3. **Decode the flag**: Extract characters at positions [52,1,28,21,30...]
4. **Submit**: `v1t{p4tch_th3_b4tch_t0_g3t_th3_s3cr3t_3nd1ng}`

### Alternative: Bypass Methods (Advanced)

**Method 1: Call result.bat directly**
```bash
result.bat unlocktheduck 8392dcc7b6fdebd5a70211c1e21497a553b31f2c70408b772c4a313615df7b60
```

**Method 2: Patch result.bat instead**
- Remove the hash check
- Force it to always show the secret flag

**Method 3: Dual patching**
- Patch game.bat to go to battle0
- Calculate the NEW hash
- Patch result.bat to accept the new hash

---

## Key Concepts for CTF Reverse Engineering

### 1. Code Flow Analysis
Look for:
- Unreachable code (battle0 was never called)
- Multiple paths to victory
- Hidden branches

### 2. Anti-Tampering
- Hash checks (SHA256, MD5)
- Checksums
- Code signing
- Self-modifying code

### 3. Obfuscation Techniques
- String encoding (Base64, hex, custom)
- Variable substitution
- Dead code injection
- Control flow flattening

### 4. Static vs Dynamic Analysis
- **Static**: Read the code without running it (what we did)
- **Dynamic**: Run and debug the program (harder with batch files)

---

## Lessons Learned

1. **Read all the code**: The secret was at the bottom (battle0)
2. **Understand the validation**: The hash check prevented simple patching
3. **Think outside the box**: You don't need to "play" the game to win
4. **Decode obfuscation**: The flag was there all along, just hidden

---

## Tools for Future Challenges

- **strings**: Extract readable strings from files
- **xxd/hexdump**: View files in hexadecimal
- **certutil**: Calculate hashes (Windows)
- **sha256sum**: Calculate hashes (Linux)
- **Python**: Perfect for decoding obfuscation
- **IDA/Ghidra**: For binary reverse engineering
- **Debuggers**: x64dbg, gdb, WinDbg
