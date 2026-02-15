# Epstein Files

## Description
You are provided with a PDF file related to an ongoing investigation. The document appears complete, but not everything is as it seems. Analyze the file carefully and recover the hidden flag. (Flag format: `pctf{...}`)

## Solution
The PDF contains 95 pages of Epstein's "black book" contacts. The flag is hidden through a 4-layer chain: a hidden PDF comment, XOR decoding, GPG decryption, and ROT18.

### Step 1: Find the hidden PDF comment
A PDF comment (lines starting with `%` are ignored by renderers) is embedded inside a StructElem dictionary at object 1730 (offset 13554619):
`%`

### Step 2: Find the XOR key from hidden text on page 94
Page 94 (0-indexed 93) contains two text strings rendered in font F12 with black color (0 0 0 rg), then covered by a near-black rectangle (0.1098 0.1098 0.1098 rg) drawn on top, making them invisible:
- `XOR_KEY` at position (422.986, 173.452)
- `JEFFREY` at position (422.986, 146.92)

This tells us: the XOR key is "JEFFREY".

### Step 3: XOR the hidden hex to get the GPG passphrase
The passphrase is `trynottogetdiddled` (lowercase).

### Step 4: Decrypt the GPG data after %%EOF
109 bytes of OpenPGP encrypted data are appended after the PDF's `%%EOF` marker. This is a SKESK v4 packet (AES256, SHA512 S2K, 52M iterations) followed by a SEIPD v1 packet.

### Step 5: ROT18 decode (ROT13 letters + ROT5 digits)
The decrypted output `cpgs{...}` has `cpgs` = ROT13 of `pctf`, and the digits are ROT5-encoded.
The flag in leetspeak reads: "AINT NO WAY HE SUICIDE" - a reference to the Epstein conspiracy.

## Flag
`pctf{41n7_n0_w4y_h3_5u1c1d3}`

## Solver Script (Key Extraction)

```python
# Script to XOR the hidden hex data with 'JEFFREY'
# Assuming we extracted the hex from the PDF stream or copy-pasted it.

def solve():
    # Hidden hex from PDF object (example placeholder)
    # Real extraction requires uncompressing PDF streams (qpdf --qdf)
    hex_data = "..." # Extracted hex string
    
    key = b"JEFFREY"
    ciphertext = bytes.fromhex(hex_data)
    
    plaintext = b""
    for i in range(len(ciphertext)):
        plaintext += bytes([ciphertext[i] ^ key[i % len(key)]])
        
    print(f"Decrypted: {plaintext}")
    # Output should correspond to GPG passphrase
    
if __name__ == "__main__":
    solve()
```

