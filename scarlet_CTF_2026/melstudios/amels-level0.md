---
ctf: ScarletCTF 2026
category: osint
difficulty: easy
points: 100
flag: RUSEC{d0wnlo4d_y0ur_fr33_c0py_t0day!}
techniques:
  - social-media-osint
  - wayback-machine
  - youtube-investigation
tools:
  - archive.org
  - bluesky
  - google
---

# Amels (Level0)

## Description

Haii!! I need your help! >_>

There's this microcelebrity girlypop game developer called [Amels](https://amels.itch.io/) I'm really fond of. I've been following her work EXTENSIVELY! on her social media!! (Call me a big fan)

(She hates alot of common social medias like Instagram, Twitter, etc., so it was really hard to find it >_<)

However, there's this new game that I really, REALLY want to play!! I've heard, from what she's been saying, that it's called **SpaceTime**, but I can't seem to find it anywhere!

Can you find the listing of the game and gain access to it? Pweeese!! I neeed to play it :(

## Solution

We're given an itch.io profile for a game developer called "Amels" and told they have a presence on a "non-mainstream" social media platform. The goal is to find the password to access the password-protected game at `https://amels.itch.io/spacetime`.

### Step 1: Find the social media profile

Since the challenge hints that the developer hates common social media like Instagram and Twitter, we focus on **alternative platforms**.

Searching on **Bluesky**, we find the profile `amels-games` (`bsky.app/profile/amels-games.bsky.social`).

### Step 2: Discover the YouTube channel

Using the **Wayback Machine** (`archive.org`), we can find archived snapshots that reveal a link to the developer's YouTube channel associated with the Bluesky profile.

### Step 3: Find the password

On the YouTube channel, there's an **accidental paste** containing the password in plain text:

```
cash-starting-distant-liable-placard
```

### Step 4: Access the game

Navigate to `https://amels.itch.io/spacetime` and enter the password to unlock the game page and retrieve the flag.

## Key Techniques

- Social media OSINT (Bluesky discovery)
- Wayback Machine for historical data
- YouTube comment/description analysis
- Password-protected content bypass

