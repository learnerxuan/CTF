# The Glitch in the Matrix - Writeup

## Challenge Description

**Category:** Steganography  
**Difficulty:** Medium  
**SHA1:** 4bbab076a0aa488761cd216a82bf4e508a2953ab  

The challenge text reads:

> The simulation is starting to fracture, and Neo can finally see the raw data stream behind the reality. During a "bullet time" glitch, he noticed that the truth isn't hidden in the whole image, but scattered within the tiniest fragments of the red signals.
>
> Morpheus left a final transmission: "To escape, you must look closely at the red pill. Collect its smallest units of information and regroup them 8 by 8 to reconstruct the message. But remember, the signal is still distorted. Only the Answer to the Ultimate Question of Life, the Universe, and Everything can unmask the final secret".

**Files provided:** `Matrix_challenge.png`

## Initial Analysis

Let's start by examining what we have:

```bash
# Verify the file hash
sha1sum Matrix_challenge.png
# Output: 4bbab076a0aa488761cd216a82bf4e508a2953ab  Matrix_challenge.png ✓

# Check basic file information
file Matrix_challenge.png
# Output: Matrix_challenge.png: PNG image data, 1500 x 1000, 8-bit/color RGB, non-interlaced

# Get image dimensions
identify Matrix_challenge.png
# Output: Matrix_challenge.png PNG 1500x1000 1500x1000+0+0 8-bit sRGB
```

The image shows the iconic "bullet time" scene from The Matrix movie where Neo dodges bullets.

## Understanding the Hints

The challenge description gives us several important clues:

1. **"tiniest fragments of the red signals"** - This refers to the **Least Significant Bits (LSB)** of the red channel
2. **"Collect its smallest units and regroup them 8 by 8"** - Extract individual bits and group them into bytes (8 bits = 1 byte)
3. **"the signal is still distorted"** - The extracted data is encrypted/encoded
4. **"Answer to the Ultimate Question of Life, the Universe, and Everything"** - This is a reference to "The Hitchhiker's Guide to the Galaxy" where the answer is **42**

## Solution Approach

Based on these hints, our approach will be:

1. Extract the Least Significant Bit (LSB) from each pixel's red channel
2. Group these bits into bytes (8 bits at a time)
3. XOR the resulting data with a key related to "42"

## Step-by-Step Solution

### Step 1: Extract LSBs from the Red Channel

Let's write a Python script to extract the LSBs:

```python
from PIL import Image

# Load the image
img = Image.open('Matrix_challenge.png')
pixels = img.load()
width, height = img.size

print(f"Image size: {width}x{height}")
print(f"Total pixels: {width * height}")

# Extract LSB from red channel
bits = []
for y in range(height):
    for x in range(width):
        r, g, b = pixels[x, y][:3]  # Get RGB values
        lsb = r & 1  # Extract least significant bit
        bits.append(lsb)

print(f"Total bits extracted: {len(bits)}")
# Output: 1,500,000 bits (1500 × 1000 pixels)
```

**What's happening here?**
- We iterate through each pixel row by row
- For each pixel, we extract the red component
- We use bitwise AND (`& 1`) to get only the least significant bit
- This gives us 1,500,000 bits total

### Step 2: Group Bits into Bytes

Now we need to convert these bits into bytes (8 bits = 1 byte):

```python
# Convert bits to bytes (MSB first)
data = []
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]  # Build byte MSB first
    data.append(byte)

print(f"Total bytes: {len(data)}")
# Output: 187,500 bytes
```

**Bit ordering explanation:**
- We're using MSB (Most Significant Bit) first ordering
- This means the first bit we read becomes the leftmost bit in the byte
- For example: bits [1,0,1,1,0,0,1,0] → byte 0b10110010 = 178

### Step 3: The XOR Key Mystery

The challenge mentions "42" but there's a twist! Let's test different interpretations:

```python
import re

# Test different XOR keys
test_keys = [
    42,      # Decimal 42
    0x42,    # Hexadecimal 42 (= decimal 66)
    66,      # Same as 0x42
]

for key in test_keys:
    print(f"\n{'='*60}")
    print(f"Testing XOR key: {key} (0x{key:02x})")
    print(f"{'='*60}")

    # XOR the data
    xored = bytes([b ^ key for b in data])

    # Convert to text
    text = xored.decode('latin-1', errors='ignore')

    # Look for flag patterns
    flags = re.findall(r'[A-Z]+\{[a-f0-9]+\}', text)

    if flags:
        print(f"FOUND FLAGS:")
        for flag in flags:
            print(f"  {flag}")

    # Show first 100 characters
    printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in text[:100])
    print(f"\nFirst 100 chars: {printable}")
```

### Step 4: The Result

When we XOR with **66** (which is **0x42** in hexadecimal), we get:

```
HACKDAY{e3a12b9383038b0c6d755bcb39d3bf879cac3750588226ba1c52d64fde0a7c96}
```

**The clever twist:** While the challenge references "42" (from Hitchhiker's Guide), the actual XOR key is **0x42** in hexadecimal, which equals **66** in decimal!

## Complete Solution Script

Here's the complete working script:

```python
#!/usr/bin/env python3
from PIL import Image
import re

def extract_lsb_steganography(image_path, xor_key):
    """
    Extract LSB steganography from red channel of an image.

    Args:
        image_path: Path to the PNG image
        xor_key: XOR key to decode the data

    Returns:
        Decoded data as bytes
    """
    # Load image
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    print(f"[+] Image dimensions: {width}x{height}")

    # Extract LSBs from red channel
    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y][:3]
            bits.append(r & 1)

    print(f"[+] Extracted {len(bits)} bits")

    # Convert bits to bytes (MSB first)
    data = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        data.append(byte)

    print(f"[+] Converted to {len(data)} bytes")

    # XOR decode
    decoded = bytes([b ^ xor_key for b in data])

    return decoded

def main():
    print("="*60)
    print("The Glitch in the Matrix - LSB Steganography Solver")
    print("="*60)

    # Extract and decode
    decoded_data = extract_lsb_steganography('Matrix_challenge.png', 0x42)

    # Convert to text
    text = decoded_data.decode('latin-1', errors='ignore')

    # Search for the flag
    print("\n[+] Searching for flag...")
    flags = re.findall(r'[A-Z]+\{[a-f0-9]+\}', text)

    if flags:
        print("\n" + "="*60)
        print("FLAG FOUND!")
        print("="*60)
        for flag in flags:
            print(f"\n{flag}\n")
    else:
        print("[-] No flag found")

    # Save decoded data
    with open('decoded_data.bin', 'wb') as f:
        f.write(decoded_data)
    print("[+] Decoded data saved to decoded_data.bin")

if __name__ == "__main__":
    main()
```

## Running the Solution

```bash
# Make sure you have PIL/Pillow installed
pip install pillow

# Run the script
python3 solve.py
```

**Output:**
```
============================================================
The Glitch in the Matrix - LSB Steganography Solver
============================================================
[+] Image dimensions: 1500x1000
[+] Extracted 1500000 bits
[+] Converted to 187500 bytes
[+] Searching for flag...

============================================================
FLAG FOUND!
============================================================

HACKDAY{e3a12b9383038b0c6d755bcb39d3bf879cac3750588226ba1c52d64fde0a7c96}

[+] Decoded data saved to decoded_data.bin
```

## Key Takeaways

1. **LSB Steganography**: Data hidden in the least significant bits of image pixels is a common steganography technique
2. **Red Channel Focus**: The challenge specifically used only the red channel, making the data extraction simpler
3. **The "42" Trick**: The clever twist was that "42" referred to hexadecimal 0x42 (decimal 66), not decimal 42
4. **Bit Ordering Matters**: Using MSB-first bit ordering was crucial for correct byte reconstruction
5. **XOR Encryption**: Simple XOR cipher was used to obfuscate the hidden message

## Flag

```
HACKDAY{e3a12b9383038b0c6d755bcb39d3bf879cac3750588226ba1c52d64fde0a7c96}
```

---

**Author's Note:** This was a well-crafted steganography challenge that combined classic LSB techniques with a clever wordplay on "42". The Matrix theme was perfectly aligned with the technical solution - seeing the "raw data stream" by extracting individual bits!
