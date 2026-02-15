---
ctf: ScarletCTF 2026
category: web
difficulty: easy
points: 100
flag: RUSEC{truly_the_hardest_ctf_challenge}
techniques:
  - http-version-downgrade
  - default-page-exploitation
  - host-header-bypass
tools:
  - curl
  - nc
---

# Commentary

## Description

You're currently speaking to my favorite **host** right now (ctf.rusec.club), but who's to say you even had to speak with one?

Sometimes, the treasure to be found is just bloat that people forgot to remove.

## Solution

The challenge hints at HTTP Host header manipulation with the bold emphasis on **host** and the phrase "who's to say you even had to speak with one?" suggesting we shouldn't need a Host header at all.

Additionally, "bloat that people forgot to remove" suggests looking for leftover files or content.

### Understanding the Vulnerability

When a web server like nginx hosts multiple virtual hosts, it uses the HTTP `Host` header to determine which site to serve. In HTTP/1.1, the Host header is **mandatory**. However, in **HTTP/1.0**, the Host header is **not required**.

By making an HTTP/1.0 request without a Host header to port 80, nginx falls back to serving its default page since it cannot determine which virtual host to route the request to.

### Exploit

```bash
# HTTP/1.0 request without Host header
printf "GET / HTTP/1.0\r\n\r\n" | nc ctf.rusec.club 80
```

This returns the default nginx welcome page, which contains an HTML comment with the flag:

```html
<!-- RUSEC{truly_the_hardest_ctf_challenge} -->
```

The "bloat people forgot to remove" refers to the default nginx page and the HTML comments containing the flag that the administrators forgot to clean up or disable.

## Key Techniques

- HTTP version downgrade (HTTP/1.0 vs HTTP/1.1)
- Virtual host fallback behavior
- Finding sensitive data in default pages/comments

