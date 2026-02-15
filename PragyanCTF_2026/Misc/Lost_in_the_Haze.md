# Lost in the Haze

## Description
A geolocation/OSINT challenge providing a Google Street View image (`whereami.png`) of a Japanese urban street. The challenge title is "Lost in the Haze" with the description: "I remember stepping outside for a moment. The air felt heavy, the lights too bright, the streets unfamiliar. All I know is that this location has a name."

Flag format: `p_ctf{ward_name}`

## Solution
The key clue is in the challenge title: "Lost in the Haze."
The word "haze" translates to **kasumi** (霞) in Japanese. The most famous location in Japan with "kasumi" in its name is **Kasumigaseki** (霞ヶ関), literally meaning "Gate of Mist/Haze." Kasumigaseki is located in **Chiyoda ward** (千代田区), Tokyo, and is well known as Japan's government district.

The image confirms a Japanese urban setting via Google Street View, showing narrow streets with a distinctive granite stone wall, vending machines, and dense residential/commercial buildings typical of central Tokyo.

Combining the linguistic hint with the visual confirmation:
- "Haze" → kasumi (霞) → Kasumigaseki (霞ヶ関) → Chiyoda ward

## Flag
`p_ctf{chiyoda}`
