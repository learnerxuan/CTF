# Crossing Boundaries

## Description
A web challenge involving cache poisoning and request smuggling (likely CL.TE or similar desync) to leak an admin bot's session cookie.

## Solution

The exploit script demonstrates a sophisticated attack:

1.  **Cache Priming:** Ensures `/blogs/<carrier>` is a cache HIT.
2.  **Poisoning the Socket (CL.TE / Smuggling):**
    -   Sends a `GET /blogs/<carrier>` request (Outer Request) with a body.
    -   The body contains a smuggled `POST /my-blogs/create` request (Inner Request).
    -   The Inner Request declares a `Content-Length` larger than the data provided.
    -   The proxy forwards this to the backend. The backend sees the Outer Request, serves it from cache (HIT), and leaves the Inner Request prefix + the "incomplete" body on the socket.
3.  **Victim (Admin Bot) Interaction:**
    -   The admin bot sends its request on the same poisoned socket.
    -   The backend concatenates the bot's request to the incomplete Inner Request body.
    -   The bot's request (including its **Session Cookie**) becomes the body of the attacker's `POST /my-blogs/create` request.
4.  **Exfiltration:**
    -   The smuggled request creates a new blog post containing the bot's request as valid content.
    -   The attacker polls their own blogs, finds the one containing the "marker" string, and extracts the admin session cookie from the blog content.
5.  **Flag Retrieval:**
    -   Uses the stolen admin session to request `/flag`.

This is a classic "Request Smuggling to Cache Poisoning to Credential Theft" chain, often seen in challenges utilizing HTTP/2 downgrades or inconsistent Content-Length parsing between proxies.

## Flag
(Retrieved dynamically by exploit script)
