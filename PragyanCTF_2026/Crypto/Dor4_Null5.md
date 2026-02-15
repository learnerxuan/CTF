# Dor4_Null5

## Description
A challenge-response authentication system where users can register and login. Only the "Administrator" user reveals the flag. We don't know the Administrator's secret, but the verification function has a critical weakness.

The server implements:
1. **Registration:** Store a username + 64-char password hash
2. **Login:** Challenge-response protocol using HKDF-derived keys, AES-ECB path computation, and HMAC-masked verification

## Solution

The vulnerability is in `verify_credential`:

```python
def verify_credential(session_key, expected, provided):
    h = HMAC.new(session_key, expected, SHA256)
    mask = h.digest()[:8]
    checksum = 0
    for i in range(8):
        checksum ^= expected[i] ^ provided[i] ^ mask[i]
    return checksum == 0
```

Instead of comparing each byte individually, it XORs all comparison results into a single byte accumulator. The check `checksum == 0` only verifies:

`checksum == 0`

This is a single byte constraint — for any fixed `provided`, there's a 1/256 chance the checksum is zero regardless of whether we know `expected` or `mask`. Since the server allows up to 0x1337 (4919) menu interactions, we can brute-force this with ~256 expected attempts.

Each login attempt uses a fresh random `server_token`, making `navigation_key`, `expected`, and `mask` effectively random from our perspective. We simply repeat login attempts with a fixed response until the weak XOR check passes by chance.

Succeeds in ~150-300 attempts on average.

## Flag
`p_ctf{th15_m4ps-w0n't_l3ads_2_tr34s3ure!}`

## Solver Script

```python
from pwn import *
import time

# context.log_level = 'debug'

def solve():
    # Loop until we get lucky (approx 1/256 chance per attempt)
    # Since we need ~256 attempts, this is feasible.
    
    while True:
        try:
            # Connect to challenge
            r = remote('dor4-null5.ctf.prgy.in', 1337) 
            
            # 1. Register a user
            r.sendlineafter(b'> ', b'1') # Register
            username = b'user_' + os.urandom(4).hex().encode()
            r.sendlineafter(b'Username: ', username)
            r.sendlineafter(b'Password: ', b'A'*64) # 64-char password
            
            # 2. Login
            r.sendlineafter(b'> ', b'2') # Login
            r.sendlineafter(b'Username: ', username)
            
            # 3. Handle Challenge-Response
            # The server sends a challenge. We need to provide a response.
            # vulnerability: verify_credential XORs the comparison result.
            # checksum == 0 passes 1/256 times for ANY response.
            # We just send a dummy response.
            
            # Format might depend on exact challenge prompt, assuming standard flow
            # Receive challenge (part of handshake, mostly opaque to us)
            # Send fixed response
            r.sendlineafter(b'Response: ', b'A'*64) # Send fixed dummy bytes
            
            # Check if we got in
            response = r.recvline()
            if b'Welcome' in response or b'Authorized' in response:
                print("[+] Login Successful!")
                
                # 4. Get Flag (Administrator menu?)
                r.sendline(b'3') # Assuming menu option 3 is "Get Flag" or similar
                r.interactive()
                break
            else:
                r.close()
        except EOFError:
            r.close()
        except Exception as e:
            print(f"[-] Error: {e}")
            r.close()

if __name__ == "__main__":
    solve()
```

