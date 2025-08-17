# Quantities CTF Challenge - QKD Cryptography Writeup

## Challenge Overview

**Challenge Name:** quantities  
**Category:** Cryptography  
**Difficulty:** Medium/Hard  
**Flag:** `flag{4b83983dc72ff21fd312db2b800075f0}`

## Challenge Description

The challenge provided three files:
- `ciphertext.hex` - Encrypted flag data
- `nonce.hex` - 12-byte cryptographic nonce
- `qkd.csv` - Quantum Key Distribution measurement data

## Initial Analysis

### Files Content
```bash
$ cat ciphertext.hex
e3b31da4bdc362f898b9adb8958ef0b8ffa9dc5e9de66b3b26348ccb57e2e70e64b76096d24c7f19728eb0fb7d6c0ca410692761daf6

$ cat nonce.hex  
5273e7b1041eeaa83c6222ff

$ head qkd.csv
AliceBasis,AliceBit,BobBasis,BobResult
Z,0,Z,0
X,0,X,0
Z,1,Z,1
Z,0,Z,0
X,0,X,0
```

### Key Observations
1. **Ciphertext:** 54 bytes of encrypted data
2. **Nonce:** 12 bytes - suggests ChaCha20 or AES-GCM
3. **QKD Data:** 560 rows of quantum measurements with Alice and Bob using different bases (Z/X) and getting bit results

## Understanding Quantum Key Distribution (QKD)

QKD is a quantum cryptographic protocol where:
- Alice sends quantum bits (qubits) to Bob
- Alice and Bob measure qubits using random bases (Z or X basis)
- They only keep bits where they used the **same measurement basis**
- Measurements with different bases are discarded as unreliable
- The shared bits form a cryptographic key

### QKD Protocol Analysis

Looking at the CSV data structure:
- `AliceBasis`: Alice's measurement basis (Z or X)
- `AliceBit`: Alice's bit value (0 or 1) 
- `BobBasis`: Bob's measurement basis (Z or X)
- `BobResult`: Bob's measured result (0 or 1)

**Key insight:** Only measurements where `AliceBasis == BobBasis` are used for key generation.

## Solution Approach

### Step 1: Extract Shared Key Bits

From the 560 total measurements, we identified 304 where Alice and Bob used the same basis:

```python
matched_measurements = []
for row in qkd_data:
    if row['AliceBasis'] == row['BobBasis']:
        matched_measurements.append(int(row['AliceBit']))
```

This gave us 304 shared key bits.

### Step 2: Key Derivation Attempts

Initially tried simple XOR decryption with various bit interpretations:
- MSB-first bit ordering
- LSB-first bit ordering  
- Different key lengths (16, 32 bytes)
- Key rotation and offsets

**Result:** Found partial flag patterns like `{..i.h.iY>d._}` but no complete flag.

### Step 3: Proper Cryptographic Analysis

The 12-byte nonce strongly suggested modern cryptographic algorithms rather than simple XOR. Attempted:

1. **ChaCha20** - No success
2. **AES-CTR** - Partial success with readable fragments
3. **AES-GCM** - **SUCCESS!**

### Step 4: Key Derivation Methods

Tested multiple key derivation approaches:

1. **Raw LSB bits** → `binary_to_bytes_lsb(qkd_bits)`
2. **Raw MSB bits** → `binary_to_bytes_msb(qkd_bits)`
3. **SHA256 of LSB** → `sha256(binary_to_bytes_lsb(qkd_bits))`
4. **SHA256 of MSB** → `sha256(binary_to_bytes_msb(qkd_bits))` ✅
5. **PBKDF2** → Key stretching with salt
6. **First 256 bits** → Direct bit extraction

## The Working Solution

**Winning combination:**
- **Algorithm:** AES-128-GCM
- **Key derivation:** SHA256 hash of MSB-ordered QKD bits
- **Key size:** 128 bits (16 bytes) 
- **Nonce:** 12 bytes as provided

### Implementation

```python
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Extract matched QKD bits
qkd_bits = []
for row in qkd_data:
    if row['AliceBasis'] == row['BobBasis']:
        qkd_bits.append(int(row['AliceBit']))

# Convert to MSB byte ordering
def binary_to_bytes_msb(bits):
    binary_str = ''.join(map(str, bits))
    padded = binary_str.ljust((len(binary_str) + 7) // 8 * 8, '0')
    return bytes(int(padded[i:i+8], 2) for i in range(0, len(padded), 8))

# Derive key using SHA256
raw_key = binary_to_bytes_msb(qkd_bits)
key = hashlib.sha256(raw_key).digest()[:16]  # AES-128 key

# Decrypt with AES-GCM
cipher = AESGCM(key)
ciphertext = bytes.fromhex("e3b31da4bdc362f898b9adb8958ef0b8ffa9dc5e9de66b3b26348ccb57e2e70e64b76096d24c7f19728eb0fb7d6c0ca410692761daf6")
nonce = bytes.fromhex("5273e7b1041eeaa83c6222ff")

# For AES-GCM, split ciphertext and auth tag
ct = ciphertext[:-16]
tag = ciphertext[-16:]
plaintext = cipher.decrypt(nonce, ct + tag, None)

print(plaintext.decode())  # flag{4b83983dc72ff21fd312db2b800075f0}
```

## Why This Worked

1. **QKD Protocol:** Correctly identified that only same-basis measurements matter
2. **Key Derivation:** SHA256 provided proper key distribution for AES
3. **MSB Ordering:** The challenge used most-significant-bit-first encoding
4. **AES-GCM:** Modern authenticated encryption with the 12-byte nonce
5. **Key Size:** AES-128 (16 bytes) was the target, not AES-256

## Lessons Learned

1. **Crypto Analysis:** Don't assume simple XOR - modern CTFs use proper cryptography
2. **QKD Understanding:** Knowing quantum protocols helped identify the key extraction method
3. **Systematic Testing:** Testing multiple key derivation methods systematically
4. **Nonce Significance:** The 12-byte nonce was a strong hint toward AES-GCM/ChaCha20
5. **Bit Ordering:** MSB vs LSB ordering can make the difference between success and failure

## Alternative Approaches That Failed

- **Simple XOR:** Too basic for modern crypto challenges
- **ChaCha20:** Wrong algorithm choice despite 12-byte nonce
- **Raw QKD bits:** Required cryptographic hashing for proper key derivation
- **LSB ordering:** Challenge used MSB bit encoding
- **Different key sizes:** AES-256 didn't work, needed AES-128

## Flag

`flag{4b83983dc72ff21fd312db2b800075f0}`

## Tools Used

- Python with `cryptography` library
- Custom QKD bit extraction scripts
- Systematic cryptographic algorithm testing

This challenge excellently combined quantum cryptography concepts with modern symmetric encryption, requiring both domain knowledge and systematic cryptanalysis skills.
