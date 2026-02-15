---
ctf: PascalCTF 2026
category: web
difficulty: easy
points: 482
flag: pascalCTF{1_h4t3_J4v45cr1pt_s0_much}
techniques:
  - jsfuck-deobfuscation
  - source-code-analysis
tools:
  - nodejs
  - browser-devtools
---

# JSHit

## Description

"I hate Javascript sooo much, maybe I'll write a website in PHP next time!"

**Category:** Web  
**Points:** 482  
**Solves:** 11

## Solution

The challenge presents a web page at `https://jshit.ctf pascalctf.it` that contains heavily obfuscated JavaScript code using **JSFuck** encoding.

JSFuck is an esoteric JavaScript style that uses only six characters: `[]()!+` to write valid JavaScript code. It works by exploiting JavaScript's type coercion system to construct strings and access object properties.

### Step 1: Identify the Obfuscation

Viewing the page source reveals a `<script id="code">` tag containing approximately 30KB of JSFuck-encoded JavaScript.

### Step 2: Decode the JSFuck

To decode JSFuck, we can use Node.js to evaluate the code without executing the final function call. The key insight is that JSFuck typically ends with `()()` which executes the constructed function. By removing the trailing `()`, we can get the function object and call `.toString()` on it:

```javascript
const fs = require('fs');

// Extract JSFuck code from HTML
const jsfuck = fs.readFileSync('page.html', 'utf8')
    .match(/<script id="code">(.*?)<\/script>/s)[1];

// Decode by evaluating without final execution
const decoded = eval(jsfuck.slice(0, -2)); // Remove trailing ()
console.log(decoded.toString());
```

### Step 3: Analyze the Decoded Code

The decoded JavaScript reveals:

```javascript
document.cookie.includes("flag=pascalCTF{1_h4t3_J4v45cr1pt_s0_much}")
```

The code checks if a cookie named `flag` equals the actual flag value. **The flag is hardcoded in the comparison!**

## Key Techniques

- JSFuck deobfuscation
- JavaScript type coercion understanding
- Source code extraction

