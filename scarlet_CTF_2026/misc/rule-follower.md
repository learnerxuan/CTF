---
ctf: ScarletCTF 2026
category: misc
difficulty: easy
points: 50
flag: RUSEC{you_read_the_rules}
techniques:
  - rule-reading
  - logic-quiz
tools:
  - nc
---

# Rule Follower

## Description

Welcome to Scarlet CTF!

This should be pretty easy for your first flag! All you gotta do is just make sure you read the rules :)

**Connection:** `nc challs.ctf.rusec.club 62075`

## Solution

Connecting to the server presents a trivia game about CTF rules with 10 TRUE/FALSE questions:

1. **You are NOT allowed to compromise/pentest our CTF platform (rCTF, scoreboard, etc.)** - TRUE
2. **Flag sharing (sharing flags to someone not on your team) is NOT allowed** - TRUE
3. **If you have a question regarding the CTF, you ping the admins or DM them** - FALSE (You make a ticket)
4. **Asking for help from other people (not on your team) for challenges is allowed if you're stuck** - FALSE
5. **You are allowed to use automated scanners/fuzzing/bruteforcing whenever you wish with NO restrictions** - FALSE (Only when a challenge specifically requires it)
6. **Your teams can be of unlimited size** - TRUE
7. **You are allowed to do ACTIVE attacking during OSINT (i.e: contacting potential targets), not just passive, when you feel it is necessary** - FALSE (OSINT is strictly passive)
8. **PASSIVE OSINT techniques are allowed on general RUSEC infrastructure only when EXPLICITLY given specific permission to by a challenge** - TRUE
9. **ACTIVE techniques (i.e: pentesting) are allowed on general RUSEC infrastructure at any time** - FALSE (Never allowed)
10. **Official writeups will be posted at the end of the competition** - TRUE

Answering all questions correctly with `T T F F F T F T F T` reveals the flag.

## Key Techniques

- Reading CTF rules carefully
- Basic logic and comprehension

