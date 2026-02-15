---
ctf: ScarletCTF 2026
category: forensics
difficulty: hard
points: 300
flag: RUSEC{87bb6410cf4d11b4220a0ff32e6d63fa95308898a8704cd9b48e5587b565f179:11/07/2021:binance}
techniques:
  - bitcoin-peel-chain
  - wallet-clustering
  - exchange-identification
tools:
  - blockstream-api
  - walletexplorer
---

# Peel That Off!

## Description

We just identified a scam cluster cashing out! Looks like the cluster is peeling off funds starting from this transaction:

`88617a44b501b2aa2ed1001a94fccbafb126578c5c2e696b20ae91dcc2a93e0a`

Can you trace through the transactions and find the end of the peel chain? Upload the transaction with the last traceable transaction in the peel chain that we can attribute as the actor from our scam cluster! We believe one of the receiving addresses will be a deposit address controlled by a cryptocurrency exchange.

**Flag format:** `RUSEC{hash:date:exchange}`

## Solution

This challenge involves Bitcoin forensics, specifically tracing a **"peel chain"** - a common money laundering technique where a scammer repeatedly sends small amounts to destinations while the bulk of the funds continue as "change" under their control.

### Step 1: Analyze the Initial Transaction

The initial transaction `88617a44b501b2aa2ed1001a94fccbafb126578c5c2e696b20ae91dcc2a93e0a` consolidates ~141 BTC from 16 inputs and has 2 outputs:

- **Output 0:** 140 BTC to `383wDR9FTSsNP5sysGSFzrjB2LNgPGCVQS` (the "change" - continues the peel chain)
- **Output 1:** ~1 BTC to `3LF39YmjoSu63SChP5MM6S3Fzo4L8zNK8N` (smaller amount)

### Step 2: Trace the Peel Chain

In a classic peel chain, the scammer keeps the larger output and "peels off" smaller amounts to various destinations:

| # | Transaction | Peeled | Remaining |
|---|-------------|--------|-----------|
| 1 | 88617a44b501b2aa... | 1 BTC | 140 BTC |
| 2 | dff53ac3f757d6ab... | 5 BTC to 16rmYLNaTU... | 135 BTC |
| 3 | b2877401b5aae57c... | 5 BTC to 16rmYLNaTU... | 130 BTC |
| ... | ... | ... | ... |
| 12 | 87bb6410cf4d11b4... | 3 BTC to 16rmYLNaTU... | 53.9 BTC (UNSPENT) |

The peel chain ends at transaction **`87bb6410cf4d11b4220a0ff32e6d63fa95308898a8704cd9b48e5587b565f179`** because the larger output (53.918 BTC) is **unspent**.

### Step 3: Identify the Exchange

The address `16rmYLNaTUqQcPnUKPEWbryXCfdV9P7W2Y` receives the "peeled" funds throughout the chain. Using WalletExplorer.com:

- It belongs to wallet `[0000011bd9]`
- Transactions from this wallet send funds to the **Binance.com** labeled wallet

This indicates that `16rmYLNaTUqQcPnUKPEWbryXCfdV9P7W2Y` is a **Binance deposit address**.

### Step 4: Extract Transaction Details

From the final transaction:
- Block height: 708681
- Block time (Unix): 1636317070
- **Date:** November 7, 2021 (**11/07/2021**)

## Key Techniques

- Bitcoin peel chain analysis
- Wallet clustering analysis
- Exchange attribution via WalletExplorer
- Transaction graph tracing

