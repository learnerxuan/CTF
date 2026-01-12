# Kelassir - CTF Challenge Writeup

## Challenge Information

- **Challenge Name:** Kelassir
- **Category:** Crypto/Steganography
- **Description:** What lies beneath is not always what it seems. Peel back every layer, decipher the secret, and claim the flag.

## Initial Analysis

We start with a single file named `kelassir`. Let's check what type of file it is:

```bash
$ file kelassir
kelassir: 7-zip archive data, version 0.4
```

The file is a 7z archive. Given the challenge description mentions "peel back every layer" and the challenge name "Kelassir" (resembling "kelasi" which could relate to layers/onions), this suggests we're dealing with nested archives.

## Solution

### Step 1: Extracting the First Layer

```bash
$ 7z x kelassir
```

This extracts a directory structure: `kelassir/kelassir` - another 7z archive!

### Step 2: Recursive Extraction with Password Discovery

Attempting to extract the second layer:

```bash
$ 7z x kelassir/kelassir
```

The archive asks for a password!

**Password Cracking:** Since the challenge name is "Kelassir", I tried common variations:
- `kelassir` ✅ **SUCCESS!**

The password is simply the challenge name in lowercase.

### Step 3: Automated Extraction Script

Given the nested nature, I created a Python script to automate the extraction:

```python
#!/usr/bin/env python3

import os
import subprocess
import shutil

PASSWORD = "kelassir"

def extract_recursive(file_path, layer=1, max_layers=200):
    """Recursively extract 7z archives with password"""
    print(f"\n{'='*50}")
    print(f"Layer {layer}")
    print(f"{'='*50}")

    # Check file type
    result = subprocess.run(['file', file_path], capture_output=True, text=True)
    file_type = result.stdout
    print(f"File: {os.path.basename(file_path)}")
    print(f"Type: {file_type.split(':')[1].strip()}")

    # Check if it's a 7z archive
    if '7-zip' not in file_type.lower():
        print(f"\nFINAL FILE REACHED!")
        return file_path

    if layer >= max_layers:
        print(f"Reached maximum layer depth ({max_layers})")
        return None

    # Extract to temporary directory
    temp_dir = f'layer_{layer}_extract'
    os.makedirs(temp_dir, exist_ok=True)

    # Extract the archive with password
    subprocess.run(
        ['7z', 'x', file_path, f'-o{temp_dir}', f'-p{PASSWORD}', '-y'],
        capture_output=True
    )

    # Find the extracted kelassir file
    extracted_file = os.path.join(temp_dir, 'kelassir', 'kelassir')

    if os.path.exists(extracted_file):
        return extract_recursive(extracted_file, layer + 1, max_layers)

    return temp_dir
```

Running this script reveals:
- Layer 1: 7z archive
- Layer 2: 7z archive (password-protected)
- Layer 3: 7z archive (password-protected)
- Layer 4: **302 individual files!** (`kelassir.000` through `kelassir.301`)

### Step 4: Analyzing the Split Files

```bash
$ ls -la layer_4_extract/kelassir/
total 1208
-rw-rw-r-- 1 xuan xuan   93 Jan 10 21:31 kelassir.000
-rw-rw-r-- 1 xuan xuan    1 Jan 10 21:19 kelassir.001
-rw-rw-r-- 1 xuan xuan    1 Jan 10 21:19 kelassir.002
...
-rw-rw-r-- 1 xuan xuan    1 Jan 10 21:19 kelassir.301
```

Most files are only 1 byte each! Let's check the first file:

```bash
$ cat kelassir.000
for f in kelassir.7z.*; do
    new="${f/kelassir.7z./kelassir.}"
    mv "$f" "$new"
done
```

This is a hint! It suggests the files should be reassembled into a 7z archive.

### Step 5: Reassembling the Archive

Concatenate files 001-301 (excluding the hint file):

```bash
$ cat kelassir.{001..301} > final.7z
$ file final.7z
final.7z: 7-zip archive data, version 0.4
```

Perfect! Now extract it:

```bash
$ 7z x final.7z -pkelassir
Everything is Ok
Folders: 1
Files: 1
```

### Step 6: Final Flag Extraction

```bash
$ cd kelassir
$ file kelassir
kelassir: ASCII text, with CRLF line terminators

$ cat kelassir
KELASSIRiKELASSIRcKELASSIRtKELASSIRfKELASSIRfKELASSIR8KELASSIR{KELASSIRmKELASSIR0KELASSIRrKELASSIR3KELASSIR_KELASSIR&KELASSIR_KELASSIRmKELASSIR0KELASSIRrKELASSIR3KELASSIR_KELASSIRkKELASSIReKELASSIRlKELASSIRaKELASSIRsKELASSIRsKELASSIRiKELASSIRrKELASSIR}
KELASSIRkKELASSIReKELASSIRlKELASSIRaKELASSIRsKELASSIRsKELASSIRiKELASSIRrKELASSIR
KELASSIR2KELASSIR0KELASSIR0KELASSIR6
```

The flag is obfuscated with "KELASSIR" between each character! Remove it:

```bash
$ cat kelassir | tr -d '\r\n' | sed 's/KELASSIR//g'
ictff8{m0r3_&_m0r3_kelassir}kelassir2006
```

## Flag

```
ictff8{m0r3_&_m0r3_kelassir}
```

## Challenge Architecture

The challenge had the following layer structure:

```
kelassir (7z archive)
└── kelassir/kelassir (7z archive, password: kelassir)
    └── kelassir/kelassir (7z archive, password: kelassir)
        └── kelassir/kelassir (7z archive, password: kelassir)
            └── 302 split files (kelassir.000 - kelassir.301)
                ├── kelassir.000 (hint script)
                └── kelassir.001-301 (1 byte each, forms 7z archive)
                    └── kelassir/kelassir (obfuscated flag)
                        └── Flag with "KELASSIR" between characters
```

## Key Takeaways

1. **Challenge Name as Hint**: The password was the challenge name itself - always try the obvious first!
2. **Layered Obfuscation**: Multiple techniques were combined:
   - Nested archives
   - Password protection
   - File splitting
   - String obfuscation
3. **Automation**: Writing scripts for recursive extraction saved significant time
4. **Attention to Details**: The hint in `kelassir.000` was crucial for understanding how to reassemble the split files
5. **Pattern Recognition**: The flag message "more & more kelassir" perfectly describes the challenge's layered nature

## Tools Used

- `7z` - 7-Zip command-line tool for archive extraction
- `file` - File type identification
- `cat` - Concatenating files
- `sed` - Text stream editing for deobfuscation
- Python - Automation scripting

## Timeline

- Initial file check: Identified 7z archive
- Password discovery: Tested challenge name variations
- Recursive extraction: 4 layers deep
- Split file analysis: 302 individual files
- Reassembly: Combined files 001-301
- Final extraction: Retrieved obfuscated flag
- Deobfuscation: Removed "KELASSIR" delimiter
