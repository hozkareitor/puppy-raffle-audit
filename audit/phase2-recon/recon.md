# 🔍 Phase 2: Reconnaissance - Puppy Raffle

## Protocol Flow Diagram

┌──────────┐ enterRaffle(address[])       ┌──────────────────┐
│ PLAYERS  │ ────────────────────────────▶│ PuppyRaffle      │
│          │                              │                  │
│          │ refund(playerIndex)          │ players[]        │
│          │ ◀─────────────────────────── │ entranceFee      │
│          │                              │ raffleDuration   │
│          │ selectWinner()               │ raffleStartTime  │
│          │ ◀───────────────────────────  totalFees  	     │
│          │                              │ previousWinner   │
│          │ withdrawFees()               └────────┬─────────┘
│          │ ◀─────────────────────────────────────┤
│          │ │ mint NFT
└──────────┘ ▼
     ┌───────────────┐
     │ PUPPY NFT     │
     │ (ERC-721)     │
     │ tokenURI()    │
     └───────────────┘

┌──────────┐ changeFeeAddress()        ┌──────────────────┐
│ OWNER    │ ────────────────────────▶ │   feeAddress     │
└──────────┘                           └──────────────────┘
text


## Identified Invariants

| # | Invariant | Risk if Broken |
|---|-----------|----------------|
| I-1 | `players.length * entranceFee == address(this).balance + totalFees` | Fund accounting mismatch |
| I-2 | No duplicate addresses in `players[]` | Multiple refunds from same player |
| I-3 | Only `msg.sender` can refund their own ticket | Unauthorized fund withdrawal |
| I-4 | `totalFees` only increases in `selectWinner()` and decreases in `withdrawFees()` | Fee drainage |
| I-5 | Winner receives exactly 80% of total pot | Unfair distribution |
| I-6 | Only 1 NFT minted per round | NFT inflation |
| I-7 | `raffleStartTime` only updated in constructor and `selectWinner()` | Temporal manipulation |
| I-8 | `tokenIdToRarity[tokenId]` is always 70, 25, or 5 | Invalid metadata |

## @Audit-Questions (Initial)

```solidity
// @Audit-Question: What if newPlayers.length = 0? Can enterRaffle be called without sending ETH?
// @Audit-Question: Is the duplicate check correct? Is there a gas issue with O(n²) nested loop?
// @Audit-Question: Can a player refund and then re-enter?
// @Audit-Question: getActivePlayerIndex returns 0 for both "not found" and index 0. How to distinguish?
// @Audit-Question: Is on-chain randomness using msg.sender + block.timestamp + block.difficulty secure?
// @Audit-Question: Can selectWinner be called with 0 active players after refunds?
// @Audit-Question: Can withdrawFees be called while players are still active?
// @Audit-Question: Is the strict equality check in withdrawFees vulnerable to DoS?
// @Audit-Question: Does 'delete players' correctly reset the array?
// @Audit-Question: Is there reentrancy risk in the ETH transfer to the winner?

