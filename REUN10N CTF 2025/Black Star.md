# Black Star - RE:union CTF 2025 Writeup

**Challenge Name:** Black Star  
**Category:** Reverse Engineering  
**Flag:** `RE:CTF{b14CKS74R_F4LLs_7rUTh_r!S3S}`

## Challenge Description

> In the void between light and shadow, a star collapses upon itself,
> consuming its own brilliance, leaving only darkness.
> What secrets does it hide within?

## Initial Analysis

The challenge provides a 32-bit ELF binary called `chall`.

```bash
file chall
# chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV)
```

### Binary Issues

The binary had multiple intentional corruptions to make analysis harder:

1. **Architecture Spoofing**: ELF header claimed to be 64-bit but was actually 32-bit
2. **Fake GLIBC Dependency**: Required non-existent `GLIBC_ABI_GNU_TLS` version
3. **Result**: Binary couldn't run directly, forcing static analysis

```bash
./chall
# Error: version `GLIBC_ABI_GNU_TLS' not found
```

## Decompiled Code Analysis

Using Ghidra to analyze the main function revealed three key components:

### 1. Key Expansion (FUN_08049600)

The binary uses a 32-byte ASCII key:
```
Key: "0123456789abcdef0123456789abcdef"
```

This key is expanded into 44 round keys using a custom algorithm similar to RC5.

### 2. Runtime Byte Rotation (FUN_080497f0)

**Critical Discovery**: The stored encrypted target is byte-rotated at runtime.

```c
void FUN_080497f0(void) {
    // For each byte in the target data:
    // byte = (byte >> 3) | (byte << 5)
    // This is a ROR 3 operation on each byte
}
```

**Important**: This happens AFTER the binary starts but BEFORE comparing user input.

### 3. Encryption Function (FUN_08049700)

Custom RC5-like block cipher with:
- Block size: 16 bytes (128 bits)
- 20 rounds
- Custom f-function: `f(x) = (2*x + 1) * x`
- Operations: XOR, rotation, addition with round keys

### 4. Input Processing

**Critical Discovery #2**: User input undergoes ROL 17 (on 64-bit words) BEFORE encryption!

```c
// For each 64-bit word of input:
local_210 = input << 0x11 | input >> 0x2f;  // ROL 17 bits
// Then encrypt
FUN_08049700(expanded_key, &local_210, &encrypted_output);
```

## The Confusion Points

### Issue 1: Byte Rotation Direction

**Question**: Should we undo or apply byte rotation?

**Answer**: The stored data at `0x0804c060` is NOT yet rotated. The `FUN_080497f0()` function applies rotation at runtime. Since we're extracting data statically, we must APPLY the rotation to simulate what the binary would do.

```python
# WRONG: Undoing rotation
unrotated = ((byte << 3) | (byte >> 5)) & 0xFF

# CORRECT: Applying rotation (simulating FUN_080497f0)
rotated = ((byte >> 3) | (byte << 5)) & 0xFF
```

### Issue 2: ROL 17 on Input

**Question**: Where does ROL 17 happen in the process?

**Answer**: The encryption flow is:
1. User input (plaintext)
2. **ROL 17 on 64-bit words** ← This step
3. Encrypt with RC5-like cipher
4. Compare with rotated target

For decryption, we reverse this:
1. Start with rotated target
2. Decrypt with RC5-like cipher
3. **ROR 17 on 64-bit words** ← Reverse step
4. Get plaintext

### Issue 3: Getting Encrypted Data

**Question**: How do we get the target encrypted data if the binary won't run?

**Answer**: Use GDB to extract raw memory even if execution fails:

```bash
pwndbg chall
break *0x08049163  # Set breakpoint at start
run
x/32xw 0x0804c060  # Dump encrypted data from memory
```

Output:
```
0x804c060: 0xc8bd703f 0x2096b2ed 0xc11a1b21 0xcbc57f70
0x804c070: 0x56dd925a 0x12f6eaf0 0x5c0fce3a 0x877cb3a3
0x804c080: 0x0b8049db 0x3e65e8bc 0x8910221f 0x221e5687
```

Length from `0x0804c044`: `0x00000030` (48 bytes = 3 blocks)

## Solution Steps

### Step 1: Extract Encrypted Data from Memory

```python
import struct

# Raw data from 0x0804c060 (BEFORE runtime rotation)
encrypted_data = [
    0xc8bd703f, 0x2096b2ed, 0xc11a1b21, 0xcbc57f70,
    0x56dd925a, 0x12f6eaf0, 0x5c0fce3a, 0x877cb3a3,
    0x0b8049db, 0x3e65e8bc, 0x8910221f, 0x221e5687
]

raw_bytes = b''.join(struct.pack('<I', x) for x in encrypted_data)
```

### Step 2: Apply Byte Rotation (Simulate FUN_080497f0)

```python
# Simulate what the binary does at runtime
rotated_target = bytearray()
for byte in raw_bytes:
    # ROR 3 on each byte
    rotated_byte = ((byte >> 3) | (byte << 5)) & 0xFF
    rotated_target.append(rotated_byte)

rotated_target = bytes(rotated_target)
```

### Step 3: Implement Key Expansion

```python
def key_expansion(key_str):
    """Expand 32-byte key into 44 round keys"""
    key_bytes = key_str.encode('ascii')
    local_40 = list(struct.unpack('<8I', key_bytes))
    
    # Initialize S-box
    param_2 = [0] * 44
    param_2[0] = 0xb7e15163  # Magic constant
    
    iVar2 = 0x5618cb1c
    for i in range(1, 44):
        param_2[i] = iVar2 & 0xFFFFFFFF
        iVar2 = (iVar2 - 0x61c88647) & 0xFFFFFFFF
    
    # Mix key with S-box (132 iterations)
    uVar3 = uVar8 = uVar6 = iVar2 = 0
    
    for _ in range(0x84):
        uVar8 = (param_2[iVar2] + uVar3 + uVar8) & 0xFFFFFFFF
        uVar8 = ((uVar8 << 3) | (uVar8 >> 29)) & 0xFFFFFFFF
        iVar4 = (uVar3 + uVar8) & 0xFFFFFFFF
        param_2[iVar2] = uVar8
        
        rot_amt = iVar4 & 0x1F
        temp = (local_40[uVar6] + iVar4) & 0xFFFFFFFF
        uVar3 = ((temp << rot_amt) | (temp >> (32 - rot_amt))) & 0xFFFFFFFF
        local_40[uVar6] = uVar3
        
        iVar2 = (iVar2 + 1) % 44
        uVar6 = (uVar6 + 1) & 7
    
    return param_2
```

### Step 4: Implement Block Decryption

```python
def rol32(val, amt):
    amt &= 0x1f
    return ((val << amt) | (val >> (32 - amt))) & 0xFFFFFFFF

def ror32(val, amt):
    amt &= 0x1f
    return ((val >> amt) | (val << (32 - amt))) & 0xFFFFFFFF

def decrypt_block(key, ct_block):
    """Decrypt one 16-byte block"""
    ct = list(struct.unpack('<4I', ct_block))
    
    # Extract final state (after 20 rounds)
    uVar11 = ct[1]
    uVar3 = ct[3]
    uVar7 = (ct[0] - key[42]) & 0xFFFFFFFF
    local_24 = (ct[2] - key[43]) & 0xFFFFFFFF
    
    # Reverse 20 rounds (from round 19 down to 0)
    for round_idx in range(19, -1, -1):
        key_idx = 2 + round_idx * 2
        
        # These were set at END of this round
        uVar10 = uVar7
        local_28 = local_24
        
        # Compute f-functions with current values
        f_left = ((2 * uVar10 + 1) * uVar10) & 0xFFFFFFFF
        f_right = ((2 * local_28 + 1) * local_28) & 0xFFFFFFFF
        
        # Rotate f values
        rot_left = rol32(f_left, 5)
        rot_right = rol32(f_right, 5)
        
        # Reverse the operations
        uVar7 = ror32((uVar3 - key[key_idx]) & 0xFFFFFFFF, rot_right & 0x1f) ^ rot_left
        local_24 = ror32((uVar11 - key[key_idx + 1]) & 0xFFFFFFFF, rot_left & 0x1f) ^ rot_right
        
        # Update for next iteration (going backwards)
        uVar11 = uVar10
        uVar3 = local_28
    
    # Reconstruct original input
    input_0 = uVar7
    input_1 = (uVar11 - key[0]) & 0xFFFFFFFF
    input_2 = local_24
    input_3 = (uVar3 - key[1]) & 0xFFFFFFFF
    
    return struct.pack('<4I', input_0, input_1, input_2, input_3)
```

### Step 5: Decrypt All Blocks

```python
key_str = "0123456789abcdef0123456789abcdef"
expanded_key = key_expansion(key_str)

# Decrypt each 16-byte block
rotated_plaintext = b''
for i in range(0, len(rotated_target), 16):
    block = rotated_target[i:i+16]
    pt_block = decrypt_block(expanded_key, block)
    rotated_plaintext += pt_block
```

### Step 6: Undo ROL 17 on Input

```python
def ror64(val, amt):
    """Rotate right 64-bit value"""
    amt &= 0x3f
    return ((val >> amt) | (val << (64 - amt))) & 0xFFFFFFFFFFFFFFFF

# Process as 64-bit words and undo ROL 17
plaintext = bytearray()
for i in range(0, len(rotated_plaintext), 8):
    qword = struct.unpack('<Q', rotated_plaintext[i:i+8])[0]
    unrotated = ror64(qword, 17)
    plaintext.extend(struct.pack('<Q', unrotated))

plaintext = bytes(plaintext)
```

### Step 7: Extract Flag

```python
flag = plaintext.decode('ascii', errors='ignore').rstrip('\x00')
print(f"Flag: {flag}")
```

## Complete Solution Script

```python
import struct

# Raw encrypted data from 0x0804c060
encrypted_data = [
    0xc8bd703f, 0x2096b2ed, 0xc11a1b21, 0xcbc57f70,
    0x56dd925a, 0x12f6eaf0, 0x5c0fce3a, 0x877cb3a3,
    0x0b8049db, 0x3e65e8bc, 0x8910221f, 0x221e5687
]

raw_bytes = b''.join(struct.pack('<I', x) for x in encrypted_data)

# Apply byte rotation (simulate FUN_080497f0)
rotated_target = bytearray()
for b in raw_bytes:
    rotated_target.append(((b >> 3) | (b << 5)) & 0xFF)
rotated_target = bytes(rotated_target)

def key_expansion(key_str):
    key_bytes = key_str.encode('ascii')
    local_40 = list(struct.unpack('<8I', key_bytes))
    param_2 = [0] * 44
    param_2[0] = 0xb7e15163
    iVar2 = 0x5618cb1c
    for i in range(1, 44):
        param_2[i] = iVar2 & 0xFFFFFFFF
        iVar2 = (iVar2 - 0x61c88647) & 0xFFFFFFFF
    uVar3 = uVar8 = uVar6 = iVar2 = 0
    for _ in range(0x84):
        uVar8 = (param_2[iVar2] + uVar3 + uVar8) & 0xFFFFFFFF
        uVar8 = ((uVar8 << 3) | (uVar8 >> 29)) & 0xFFFFFFFF
        iVar4 = (uVar3 + uVar8) & 0xFFFFFFFF
        param_2[iVar2] = uVar8
        rot_amt = iVar4 & 0x1F
        temp = (local_40[uVar6] + iVar4) & 0xFFFFFFFF
        uVar3 = ((temp << rot_amt) | (temp >> (32 - rot_amt))) & 0xFFFFFFFF
        local_40[uVar6] = uVar3
        iVar2 = (iVar2 + 1) % 44
        uVar6 = (uVar6 + 1) & 7
    return param_2

def rol32(val, amt):
    amt &= 0x1f
    return ((val << amt) | (val >> (32 - amt))) & 0xFFFFFFFF

def ror32(val, amt):
    amt &= 0x1f
    return ((val >> amt) | (val << (32 - amt))) & 0xFFFFFFFF

def ror64(val, amt):
    amt &= 0x3f
    return ((val >> amt) | (val << (64 - amt))) & 0xFFFFFFFFFFFFFFFF

def decrypt_block(key, ct):
    ct = list(struct.unpack('<4I', ct))
    uVar11, uVar3 = ct[1], ct[3]
    uVar7 = (ct[0] - key[42]) & 0xFFFFFFFF
    local_24 = (ct[2] - key[43]) & 0xFFFFFFFF
    
    for r in range(19, -1, -1):
        k = 2 + r * 2
        uVar10, local_28 = uVar7, local_24
        f_l = ((2 * uVar10 + 1) * uVar10) & 0xFFFFFFFF
        f_r = ((2 * local_28 + 1) * local_28) & 0xFFFFFFFF
        rot_l, rot_r = rol32(f_l, 5), rol32(f_r, 5)
        uVar7 = ror32((uVar3 - key[k]) & 0xFFFFFFFF, rot_r & 0x1f) ^ rot_l
        local_24 = ror32((uVar11 - key[k+1]) & 0xFFFFFFFF, rot_l & 0x1f) ^ rot_r
        uVar11, uVar3 = uVar10, local_28
    
    return struct.pack('<4I', uVar7, (uVar11 - key[0]) & 0xFFFFFFFF, 
                       local_24, (uVar3 - key[1]) & 0xFFFFFFFF)

# Decrypt
key = "0123456789abcdef0123456789abcdef"
expanded_key = key_expansion(key)

rotated_pt = b''.join(decrypt_block(expanded_key, rotated_target[i:i+16]) 
                      for i in range(0, len(rotated_target), 16))

# Undo ROL 17
plaintext = b''.join(struct.pack('<Q', ror64(struct.unpack('<Q', rotated_pt[i:i+8])[0], 17)) 
                     for i in range(0, len(rotated_pt), 8))

flag = plaintext.decode('ascii', errors='ignore').rstrip('\x00')
print(f"Flag: {flag}")
```

## Running the Solution

```bash
python3 solve.py
# Flag: RE:CTF{b14CKS74R_F4LLs_7rUTh_r!S3S}
```

## Key Takeaways

1. **Static Analysis is Powerful**: When a binary won't run, you can still extract and analyze data using GDB
2. **Follow the Data Flow**: Understanding the exact order of operations (byte rotation → encryption → ROL 17) was critical
3. **Test Your Assumptions**: The round-trip encrypt/decrypt test verified the algorithm worked correctly
4. **Byte Order Matters**: Little-endian encoding affects how data is interpreted from memory dumps
5. **Runtime vs. Static Data**: The stored target data was NOT yet rotated - rotation happened at runtime

## Algorithm Summary

The "Black Star" cipher is a custom block cipher with these characteristics:

- **Block Size**: 128 bits (16 bytes)
- **Key Size**: 256 bits (32 bytes)
- **Rounds**: 20
- **Key Schedule**: RC5-inspired expansion to 44 round keys
- **f-function**: `f(x) = (2x + 1) × x` (data-dependent rotation)
- **Operations**: XOR, ADD, ROL/ROR
- **Pre-processing**: ROL 17 on input (64-bit words)
- **Post-processing**: ROR 3 on each byte of target (runtime)

The cipher combines elements of RC5 and TEA, with custom modifications to make analysis more challenging.
