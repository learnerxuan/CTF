# Packer Challenge - Reverse Engineering Writeup

## Challenge Information

- **Name:** Packer
- **Category:** Reverse Engineering
- **Description:** Reverse this Linux executable?
- **Hint:** What can we do to reduce the size of a binary after compiling it?

## Overview

This challenge involves analyzing a packed Linux executable. From the challenge name "Packer", we can infer that the binary has been compressed or obfuscated using a packing tool.

### What is a Packer?

A **packer** is a tool used to compress and modify executable files to:
- Reduce file size
- Protect binaries from reverse engineering
- Obfuscate code structure

Packers work by rearranging and encoding the original binary, often embedding a decompression routine that restores the program during execution.

## Solution Process

### Step 1: Initial Binary Analysis

First, let's examine the file type using the `file` command:

```bash
file out
```

![File command output](https://github.com/user-attachments/assets/7dcd7e7f-b90f-45a6-9290-c0f99fe11cc4)

**Output Analysis:**
```
ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, no section header
```

**Key Observations:**
- **ELF 64-bit LSB executable, x86-64**: Standard Linux 64-bit executable with Little-Endian byte order
- **statically linked**: All library code is compiled directly into the executable (larger file size)
- **no section header**: Unusual - indicates the binary has been stripped/packed for anti-analysis

### Step 2: String Analysis

Let's search for readable strings in the binary:

```bash
strings out
```

![Strings command output showing UPX](https://github.com/user-attachments/assets/18a5b609-d50a-459a-b431-3c7a5bbb95cd)

**Discovery:** The strings output reveals **UPX** signatures, indicating the binary was packed with UPX (Ultimate Packer for eXecutables).

### Step 3: Understanding UPX

**UPX (Ultimate Packer for eXecutables)** is an open-source executable packer that:
- Compresses executables using advanced algorithms
- Maintains functionality while reducing file size
- Automatically decompresses during execution
- Supports multiple platforms (Windows, Linux, macOS, DOS, etc.)

**Common UPX Commands:**
```bash
# Pack a program
upx myprogram

# Unpack a program
upx -d myprogram

# Unpack with custom output name
upx -d input_file -o output_file
```

### Step 4: Unpacking the Binary

Now that we know it's UPX-packed, let's unpack it:

```bash
upx -d out -o original
```

![UPX unpacking command](https://github.com/user-attachments/assets/2c8a68b2-c9ff-4477-ad27-1f57696ce7c7)

This command:
- `-d`: Decompress/unpack the file
- `out`: Input packed file
- `-o original`: Output unpacked file as "original"

### Step 5: Analyzing the Unpacked Binary

Run strings analysis on the unpacked binary:

```bash
strings original
```

![Strings output from unpacked binary showing hex string](https://github.com/user-attachments/assets/957bebc9-b0f5-41d9-9e0f-6e35b0df7dc8)

**Discovery:** We find an interesting hex string:
```
7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f62646438343839337d
```

### Step 6: Flag Extraction

We can decode this hex string using multiple methods:

#### Method 1: Command Line (xxd)
```bash
echo '7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f62646438343839337d' | xxd -r -p
```

![Flag extraction using xxd command](https://github.com/user-attachments/assets/af2f012c-4695-4128-89fe-8613181a731c)

**Command Breakdown:**
- `echo '...'`: Outputs the hex string
- `|`: Pipes output to next command
- `xxd -r -p`: Converts hex to ASCII
  - `-r` (reverse): Convert from hex to ASCII
  - `-p` (plain): Treat input as continuous hex stream

#### Method 2: CyberChef
You can also use [CyberChef](https://gchq.github.io/CyberChef/) with the "Magic" operation or "From Hex" operation to decode the string.

![CyberChef Magic operation decoding the hex string](https://github.com/user-attachments/assets/4ae3819f-1dcd-4f69-9a91-6cb79b508f9b)

## Flag

```
picoCTF{U9X_UnP4ck1N6_B1n4Ri3S_bdd84893}
```

## Key Learning Points

1. **File Analysis**: Always start with `file` command to understand binary structure
2. **String Analysis**: Use `strings` to identify packer signatures and embedded data
3. **Packer Recognition**: UPX is a common packer in CTF challenges
4. **Unpacking Tools**: UPX provides built-in unpacking with `-d` flag
5. **Data Encoding**: Hex-encoded strings are common ways to hide flags in binaries

## Tools Used

- `file` - File type identification
- `strings` - Extract readable strings from binaries
- `upx` - UPX packer/unpacker
- `xxd` - Hex dump and reverse operations
- `echo` - Output text to stdout

## Alternative Solutions

For hex decoding, you could also use:
```bash
# Using python
python3 -c "print(bytes.fromhex('7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f62646438343839337d').decode())"

# Using perl
perl -pe 's/([0-9a-f]{2})/chr(hex($1))/gie' <<< "7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f62646438343839337d"
```

---

**Challenge completed successfully! 🚩**
