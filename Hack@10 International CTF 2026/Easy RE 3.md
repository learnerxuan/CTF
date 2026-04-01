# Easy RE 3 Writeup

## Target

- Challenge binary: `challenge`
- Encrypted files: `what.enc`, `nonogpt.enc`
- Binary SHA256: `79d28f0b0269dcf6e8062ef4bf22afde76b5dcb6d926bc9e95d4c2a8e1f12ecd`
- Final flag: `hack10{H0w_u_f1nd_me}`

## Executive Summary

This challenge is built around version confusion. The binary contains multiple related crypto paths, and the obvious path is intentionally misleading.

The file `nonogpt.enc` decrypts cleanly with the current uppercase `D` mode and produces a valid JPEG, but that image is a decoy and does not contain the accepted flag. The real flag comes from `what.enc`, which was produced by an older `e`-mode format that is not compatible with the current `D` decrypt routine.

The solve therefore required recovering the older encryption format from `_main`, inverting it, and decrypting `what.enc` with the correct runtime assumptions for macOS ARM64. The flag itself is then read from the recovered image.

## Initial Triage

Useful first-pass commands:

```bash
file challenge what.enc nonogpt.enc
rabin2 -I challenge
rabin2 -S challenge
rabin2 -i challenge
rabin2 -z challenge
```

Relevant observations:

- `challenge` is a stripped Mach-O 64-bit ARM64 macOS binary.
- The binary exposes only three meaningful internal routines after stripping:
  - `_main` at `0x100000598`
  - VM constant decoder at `0x100001edc`
  - stream/helper transform at `0x100002378`
- The challenge hint about version confusion is accurate. Both `.enc` files are valid outputs, but they correspond to different format revisions.

## False Lead: `nonogpt.enc`

The current uppercase `D` path is fully valid for `nonogpt.enc`.

Recovered current-format structure:

- bytes `0..3`: original plaintext size, big-endian
- bytes `4..11`: 8-byte IV
- body: ciphertext

Recovered current-format decrypt path:

1. derive helper seed from `DEADC0DE ^ size`
2. derive TEA key bytes from an LCG stream
3. TEA-CBC decrypt
4. XOR with LCG byte stream
5. apply the helper transform

That path decrypts `nonogpt.enc` into a valid JPEG. However, it does not yield the accepted challenge flag. This file is the intended decoy.

## Real Pivot: `what.enc` Uses the Old `e` Format

`what.enc` does not decrypt correctly under the current uppercase `D` implementation. That ruled out a single-format challenge and forced analysis of the older `e` branch inside `_main`.

The critical insight was:

- `nonogpt.enc` matches the current decrypt implementation
- `what.enc` matches an older encryption implementation
- the binary contains enough logic to recover that older format

## Recovering the Old Format

Static analysis alone was enough to identify the broad stages, but the function is flattened heavily enough that emulating `_main` was the fastest way to verify the exact behavior.

I used a small Unicorn-based harness to run the binary’s `e` mode on controlled sample plaintext and trace the internal state. That let me confirm the exact block primitive, the CBC chaining, and the runtime-dependent key mutation.

### Verified old `e` pipeline

For a plaintext of length `N`, the old format is:

1. Apply the helper transform with seed input `DEADC0DE ^ N`
2. XOR the result with the raw LCG stream
3. Apply PKCS#7 padding to 8-byte blocks
4. Encrypt in CBC-style mode with a custom TEA-like block primitive
5. Write output as:
   - `BE32(N)`
   - 8-byte IV
   - ciphertext

### Verified IV schedule

The IV schedule is still:

```text
lcg_bytes(seed, 8, mask=0x37, skip=N+17)
```

This matches both the current and old formats.

### Verified raw key schedule

The raw 16 key bytes are:

```text
lcg_bytes(seed, 16, mask=0x26, skip=N+1)
```

But in the old format, these bytes are not used directly.

### Verified old key mutation

The old branch mutates the key words using:

- `m0 = DAT_100008018 XOR getpagesize()`
- `m1 = DAT_10000801C XOR original_size`
- `m2 = m0 XOR m1`
- `m3 = ~m2`

Then:

```text
final_key_words = raw_key_words XOR [m0, m1, m2, m3]
```

This runtime dependency on `getpagesize()` is the main reason naïve reconstruction failed at first.

## The Important Environment Detail

The correct page size for the successful decrypt is:

```text
0x4000
```

This matches Apple Silicon/macOS behavior and is the value that makes `what.enc` decrypt cleanly. Using `0x1000` produces invalid padding and garbage output.

That was the final missing piece.

## Old Block Primitive

The old block cipher is TEA-like, but not stock TEA as usually written in scripts.

Verified behavior:

- 32 rounds
- delta `0x9E3779B9`
- block split as:
  - `w0 = le32(block[0:4])`
  - `w1 = le32(block[4:8])`
- internal state uses reversed semantic roles:
  - `v0 = w1`
  - `v1 = w0`
- round update:

```text
v1 += ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (key[sum & 3] + sum))
sum += delta
v0 += ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (key[(sum >> 11) & 3] + sum))
```

- output block is:

```text
le32(v1) || le32(v0)
```

The chaining mode is CBC-style:

- first block input = preprocessed plaintext block XOR IV
- next block input = preprocessed plaintext block XOR previous ciphertext block

## Standalone Decryptor

Below is a self-contained decryptor that reproduces the decrypt of `what.enc` and writes the recovered JPEG as `what_old.dec`.

It assumes `challenge` and `what.enc` are in the current working directory.

```python
#!/usr/bin/env python3
import struct
from pathlib import Path

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import (
    UC_ARM64_REG_SP,
    UC_ARM64_REG_X0,
    UC_ARM64_REG_X1,
    UC_ARM64_REG_X2,
    UC_ARM64_REG_X3,
    UC_ARM64_REG_X30,
)


CHALL = Path("challenge")
WHAT = Path("what.enc")
OUT = Path("what_old.dec")

BASE = 0x100002000
SIZE = 0x8000
STACK = 0x40000000
STACK_SIZE = 0x20000
BUF = 0x50000000
GUARD_PTR = 0x100014000
GUARD = 0x1122334455667788
CODE_ADDR = 0x100002378
END = 0x1000026D4

LCG_A = 0x343FD
LCG_C = 0x269EC3

DAT_100008018 = 0xC0DEBABE
DAT_10000801C = 0xDECEA5ED


def helper_blob() -> bytes:
    data = CHALL.read_bytes()
    return data[0x2000:0x4100] + b"\x00" * (SIZE - (0x4100 - 0x2000))


def helper_transform(buf: bytes, orig_size: int) -> tuple[bytes, int]:
    mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    mu.mem_map(BASE, SIZE)
    mu.mem_write(BASE, helper_blob())
    mu.mem_map(GUARD_PTR & ~0xFFF, 0x1000)
    mu.mem_write(0x100004008, GUARD_PTR.to_bytes(8, "little"))
    mu.mem_write(GUARD_PTR, GUARD.to_bytes(8, "little"))
    for addr, value in {
        0x100008000: 0xDEADC0DE,
        0x100008004: 0xF00DABCD,
        0x100008008: 0x13371347,
        0x10000800C: 0x9E3779B1,
        0x100008010: 0x2026,
        0x100008014: 0x1337,
        0x100008018: DAT_100008018,
        0x10000801C: DAT_10000801C,
    }.items():
        mu.mem_write(addr, value.to_bytes(4, "little"))
    mu.mem_map(STACK, STACK_SIZE)
    bufsz = ((len(buf) + 0x1000 + 0xFFF) // 0x1000) * 0x1000
    mu.mem_map(BUF, bufsz)
    mu.mem_write(BUF, buf)
    outptr = BUF + len(buf) + 0x100
    mu.mem_write(outptr, b"\x00" * 8)
    mu.reg_write(UC_ARM64_REG_SP, STACK + STACK_SIZE - 0x1000)
    mu.reg_write(UC_ARM64_REG_X0, BUF)
    mu.reg_write(UC_ARM64_REG_X1, len(buf))
    mu.reg_write(UC_ARM64_REG_X2, 0xDEADC0DE ^ orig_size)
    mu.reg_write(UC_ARM64_REG_X3, outptr)
    mu.reg_write(UC_ARM64_REG_X30, 0xDEADBEEFCAFEBABE)
    mu.emu_start(CODE_ADDR, END)
    out = bytes(mu.mem_read(BUF, len(buf)))
    seed = int.from_bytes(mu.mem_read(outptr, 4), "little")
    return out, seed


def lcg_bytes(seed: int, n: int, mask: int = 0, skip: int = 0) -> tuple[bytes, int]:
    state = seed
    for _ in range(skip):
        state = (state * LCG_A + LCG_C) & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        state = (state * LCG_A + LCG_C) & 0xFFFFFFFF
        out.append(((state >> 16) & 0xFF) ^ mask)
    return bytes(out), state


def mutate_key(raw_key: bytes, orig_size: int, page_size: int = 0x4000) -> bytes:
    rk = list(struct.unpack("<4I", raw_key))
    m0 = DAT_100008018 ^ page_size
    m1 = DAT_10000801C ^ orig_size
    m2 = m0 ^ m1
    m3 = (~m2) & 0xFFFFFFFF
    out = [rk[0] ^ m0, rk[1] ^ m1, rk[2] ^ m2, rk[3] ^ m3]
    return struct.pack("<4I", *out)


def old_e_dec_block(block: bytes, key_bytes: bytes) -> bytes:
    v1 = struct.unpack("<I", block[:4])[0]
    v0 = struct.unpack("<I", block[4:])[0]
    key = list(struct.unpack("<4I", key_bytes))
    total = 0xC6EF3720
    delta = 0x9E3779B9
    for _ in range(32):
        v0 = (v0 - ((((v1 << 4) & 0xFFFFFFFF) ^ (v1 >> 5)) + v1 ^ ((key[(total >> 11) & 3] + total) & 0xFFFFFFFF))) & 0xFFFFFFFF
        total = (total - delta) & 0xFFFFFFFF
        v1 = (v1 - ((((v0 << 4) & 0xFFFFFFFF) ^ (v0 >> 5)) + v0 ^ ((key[total & 3] + total) & 0xFFFFFFFF))) & 0xFFFFFFFF
    return struct.pack("<I", v1) + struct.pack("<I", v0)


def pkcs7_unpad(data: bytes, block_size: int = 8) -> bytes:
    pad = data[-1]
    if pad == 0 or pad > block_size or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad]


def decrypt_old_e(enc: bytes, page_size: int = 0x4000) -> tuple[bytes, dict]:
    orig_size = int.from_bytes(enc[:4], "big")
    iv = enc[4:12]
    ciphertext = enc[12:]
    _, seed = helper_transform(b"\x00" * orig_size, orig_size)

    derived_iv, _ = lcg_bytes(seed, 8, mask=0x37, skip=orig_size + 17)
    raw_key, _ = lcg_bytes(seed, 16, mask=0x26, skip=orig_size + 1)
    key = mutate_key(raw_key, orig_size, page_size=page_size)

    prev = iv
    padded = bytearray()
    for i in range(0, len(ciphertext), 8):
        c = ciphertext[i:i + 8]
        block = old_e_dec_block(c, key)
        padded.extend(bytes(a ^ b for a, b in zip(block, prev)))
        prev = c

    stage2 = pkcs7_unpad(bytes(padded))
    stream, _ = lcg_bytes(seed, orig_size, skip=0)
    helper_out = bytes(a ^ b for a, b in zip(stage2, stream))
    plaintext, _ = helper_transform(helper_out, orig_size)
    meta = {
        "orig_size": orig_size,
        "header_iv_hex": iv.hex(),
        "derived_iv_hex": derived_iv.hex(),
        "seed_hex": f"0x{seed:08x}",
        "raw_key_hex": raw_key.hex(),
        "mutated_key_hex": key.hex(),
        "page_size_hex": hex(page_size),
    }
    return plaintext[:orig_size], meta


def main() -> None:
    plaintext, meta = decrypt_old_e(WHAT.read_bytes(), page_size=0x4000)
    OUT.write_bytes(plaintext)
    print(meta)
    print("output=what_old.dec")


if __name__ == "__main__":
    main()
```

Run it with:

```bash
python3 solve.py
```

Expected output:

```text
{'orig_size': 194652, 'header_iv_hex': 'bfa8499167aafc01', 'derived_iv_hex': 'bfa8499167aafc01', 'seed_hex': '0x240d919a', 'raw_key_hex': '15e7901605f702602606efc29b45f7b0', 'mutated_key_hex': 'ab1d4ed6b4aacebe29a1fddc6b1d1a51', 'page_size_hex': '0x4000'}
output=what_old.dec
```

The resulting JPEG is the important artifact. The decryptor does not print the flag as text. After opening `what_old.dec`, the flag can be read directly from the image:

```text
hack10{H0w_u_f1nd_me}
```

## Final Result

```text
hack10{H0w_u_f1nd_me}
```
      
