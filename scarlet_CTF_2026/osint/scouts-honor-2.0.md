---
ctf: ScarletCTF 2026
category: osint
difficulty: medium
points: 200
flag: RUSEC{ISSN-0006-8608_THE-VOICE-OF-LABOR}
techniques:
  - magazine-research
  - issn-lookup
  - newspaper-archives
  - historical-research
tools:
  - google
  - issn-portal
  - newspaper-archives
---

# Scouts Honor 2.0

## Description

This OSINT challenge consists of two parts.

**Part 1:** Identify a childhood magazine published by a historic civic organization using the clues:
- Mentions of the Olympics
- A funny mail burro who loves alfalfa
- Something called "Cheetah Hunt"

Then find the ISSN number of that magazine.

**Part 2:** Find a World War I era newspaper from one of the three Rutgers University campus cities (New Brunswick, Newark, Camden). The newspaper must mention a historic boy-led organization and state that General McAlpin was its President.

**Flag format:** `RUSEC{ISSN-1234-5678_NAME-OF-NEWSPAPER}`

## Solution

### Part 1 — The Magazine

The challenge mentions a "historic civic organization," which strongly points to the **Boy Scouts of America**.

Their long-running magazine is **Boys' Life**, first published in 1911 (renamed Scout Life in 2021).

#### Clue Matching

Each clue matches known Boys' Life content:

1. **Mail burro who loves alfalfa**  
   This refers to **Pedro the Mailburro**, Boys' Life's long-running mascot since 1947. Pedro appears in comic strips and reader mail sections and is famous for loving alfalfa.

2. **Olympics**  
   Boys' Life regularly publishes Olympic features and athlete spotlights (for example, London 2012 coverage).

3. **"Cheetah Hunt"**  
   This refers to a feature on the Cheetah Hunt roller coaster at Busch Gardens Tampa, which opened in 2011 and was covered in youth magazines.

Together, these clues clearly identify **Boys' Life**.

#### ISSN

Looking up Boys' Life in the ISSN Portal and library catalogs gives:

**Boys' Life (Print) ISSN: 0006-8608**

So Part 1 = `ISSN-0006-8608`

### Part 2 — The Newspaper

The "historic boy-led organization" mentioned is the **American Boy Scouts**, later renamed the **United States Boy Scouts (USBS)**. This was a rival organization to the Boy Scouts of America, founded in 1910.

#### General McAlpin

- General Edwin A. McAlpin
- President and Chief Scout of the American Boy Scouts / USBS
- Served until his death in April 1917 (during World War I)

So the newspaper must be from the WWI era and mention McAlpin as President.

#### Finding the Newspaper

Searching digitized WWI-era New Jersey newspapers leads to a Camden labor newspaper called:

**The Voice of Labor** (Camden, New Jersey)

This paper ran from 1915–1917 and covered national political and civic issues. A 1916 issue contains an article referencing:

"General McAlpin, President of the U.S. Boy Scouts…"

This directly matches the challenge description:
- WWI era ✓
- Rutgers campus city (Camden) ✓
- Mentions General McAlpin as President ✓
- Mentions the historic boy-led organization ✓

## Key Techniques

- Historical magazine research
- ISSN database lookup
- Digitized newspaper archive searching
- Cross-referencing historical organizations

