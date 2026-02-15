---
ctf: PascalCTF 2026
category: misc
difficulty: medium
points: 496
flag: pascalCTF{35.92,14.47}
techniques:
  - geosint
  - architectural-analysis
  - shop-identification
tools:
  - google-maps
  - reverse-image-search
---

# Geoguesser

## Description

"Alan Spendaccione accumulated so much debts that he travelled far away to escape Fabio Mafioso, join the mafia and help Fabio catch Alan!"

**Flag format:** `pascalCTF{YY.YY,XX.XX}` where Y=latitude and X=longitude, round the numbers down.

**Category:** misc  
**Points:** 496  
**Solves:** 6

## Solution

### Location

**C'est La Vie Boutik, Swieqi, Malta**  
**Coordinates:** 35.9212° N, 14.4792° E (rounded down to **35.92, 14.47**)

### Analysis Approach

#### 1. Image Analysis

The challenge image contained several identifying features:
- Person standing at a road junction with "STOP" painted on the road
- Multi-story residential buildings with distinctive **enclosed wooden balconies** (Maltese gallarija)
- Telecommunications tower visible in the background
- Hilly terrain with buildings in the background
- Yellow curb markings and orange traffic cone
- **Key clue:** Shop sign for "C'est La Vie Boutik" visible in the image

#### 2. Country Identification

The architecture strongly indicated **Malta**:
- The enclosed wooden balconies are called "gallarija" - a distinctive Maltese architectural feature
- English "STOP" road markings (Malta uses British-influenced road signs)
- Mediterranean limestone construction typical of Malta
- Left-hand traffic infrastructure (Malta was a British colony)

#### 3. Pinpointing the Location

- The shop sign "C'est La Vie Boutik" was the key identifier
- This boutique is located in **Swieqi, Malta**
- Swieqi is a residential town in the Eastern Region of Malta, near St. Julian's and Paceville

#### 4. Calculating Coordinates

- Exact coordinates: 35.9212° N, 14.4792° E
- **Rounded DOWN** (floor function): 35.92, 14.47

## Key Techniques

- Architectural feature identification (Maltese gallarija)
- Shop/business name OSINT
- Google Maps location verification
- Coordinate precision and rounding

