---
ctf: ScarletCTF 2026
category: forensics
difficulty: medium
points: 200
flag: RUSEC{57ce32d129f4824aa8c7e71e56cf4908dcc32103f5fff3c3d6a08bd7bae78c48}
techniques:
  - bitcoin-forensics
  - blockchain-analysis
  - transaction-tracing
tools:
  - blockstream-api
  - blockchain-explorer
---

# Dark Tracers

## Description

A forensics challenge involving Bitcoin transaction tracing. We're given an initial transaction from a Bitcoin ATM (`427e04420fffc36e7548774d1220dad1d20c1c78dd71ad2e1e9fd1751917a035`) and tasked with finding the transaction hash representing the payment from a perpetrator to a scammer in a murder-for-hire case.

The case references a real DOJ press release about Michelle Murphy, who was sentenced to 9 years for attempting to pay $10,510 in Bitcoin to hire a hitman on the dark web.

## Solution

### 1. Analyzed the initial ATM transaction

The transaction `427e04420fffc36e7548774d1220dad1d20c1c78dd71ad2e1e9fd1751917a035` sent funds to two addresses:
- `bc1qadgwek3qhng2jfc25epwuvg4cfsuq3dy4p8ccj` (23,393,837 satoshis)
- `bc1qt33f8ya0w4ges34f23a0xtkvflzutn0u2gy3gl` (34,112,412 satoshis)

### 2. Researched the case

From news articles, the agreed payment was **$10,510 in Bitcoin**. With BTC at ~$29,180 on July 27, 2023, this equals approximately **36,000,000 satoshis** (~0.36 BTC).

### 3. Traced the transaction chain

The first address (`bc1qadgwek3qhng2jfc25epwuvg4cfsuq3dy4p8ccj`) received multiple deposits from Bitcoin ATMs (matching the case details that the perpetrator used ATMs "on at least three occasions"):

- 23,393,837 satoshis (from initial transaction)
- 8,073,634 satoshis (tx a6754898...)
- 8,167,038 satoshis (tx a543237f...)

### 4. Found the consolidation

These funds were consolidated in transaction `2503bad8b5a1b4ff4555c28632475cd148a96e631ee1fdee0935b2b487c63ae1`, sending 39,630,365 satoshis to `bc1q44mw0cffurnex8jxqvtvap3fwv3et0v9lxdc3t`.

### 5. Identified the payment

Transaction **`57ce32d129f4824aa8c7e71e56cf4908dcc32103f5fff3c3d6a08bd7bae78c48`** sent:
- **35,848,829 satoshis** (~$10,456 at the time) to `1DyodhmYorFDcPRSmJt49bs6Wh559K6FSN`
- 3,780,360 satoshis to another address

This matches the $10,510 payment amount from the case!

## Key Techniques

- Bitcoin blockchain forensics
- Transaction graph analysis
- Satoshi-to-USD conversion
- Real-world case correlation

