---
ctf: VUWCTF 2025
category: rev
difficulty: easy
points: 484
flag: "VuwCTF{The_L3phant_1s_TRiang1efied}"
techniques: [image_encryption, opencv, xor_cipher, smoothness_analysis]
tools: [python, opencv, numpy]
---

# Trianglification

## Description
An image encryption tool using OpenCV with a triangle-based XOR encryption scheme.

## Solution

### Understanding the Encryption

Reversing the binary reveals it's an image encryption tool using OpenCV. The encryption scheme:

1. Divides the image into 5 regions based on a triangle with vertices at (89,44), (49,124), (129,124)
2. The triangle is subdivided by midpoints into regions: above, left, right, under, and inside
3. Each region has a random mask value (0-255)
4. For each pixel at (x,y), the XOR key is computed as: `key = (mask * x - y) & 0xFF`
5. Pixels in overlapping regions XOR their masks together

### Breaking the Encryption

The key insight is that natural images have smooth gradients - neighboring pixels have similar values. We can exploit this to recover the masks:

1. **Identify "pure" pixels** - pixels that belong to exactly one region (for clean mask recovery)
2. **Brute-force each mask** - for each region, try all 256 possible mask values
3. **Score by smoothness** - decrypt sample pixels and measure the difference between neighboring pixels; the correct mask produces the smoothest result

**Smoothness Cost Function:**
```python
def smoothness_cost(region_points, mask_val):
    """Lower cost = smoother result = correct mask"""
    cost = 0
    for x, y in region_points:
        key = (mask_val * x - y) & 0xFF
        dec = img[y, x] ^ key
        # Compare with neighbors
        if x + 1 < w:
            key2 = (mask_val * (x + 1) - y) & 0xFF
            dec2 = img[y, x + 1] ^ key2
            cost += abs(dec - dec2)
    return cost
```

### Full Decryption

Once masks are recovered, decrypt each pixel using the region-based XOR scheme:

```python
def decrypt_with_masks(mask_dict):
    for y in range(h):
        for x in range(w):
            # XOR together masks of all regions this pixel belongs to
            mask = 0
            if is_above(x,y): mask ^= mask_dict['above']
            if is_right(x,y): mask ^= mask_dict['right']
            if is_left(x,y):  mask ^= mask_dict['left']
            if is_under(x,y): mask ^= mask_dict['under']
            if is_inside(x,y): mask ^= mask_dict['inside']

            key = (mask * x - y) & 0xFF
            out[y, x] = img[y, x] ^ key
    return out
```

The decrypted image reveals an elephant with the flag text overlaid.

**Full solver script (149 lines):** View in [clean_code_157.txt](file:///c:/Users/User/OneDrive/Desktop/CTF%20writeups/CTF/clean_code_157.txt)

## Key Techniques
- Image-based cryptanalysis
- Triangle geometry and region subdivision
- Brute-force mask recovery via smoothness scoring
- Pixel neighborhood gradient analysis
- OpenCV image manipulation
