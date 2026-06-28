# Puppy Raffle - Smart Contract Security Audit Report

**Auditor:** hozkareitor  
**Date:** June 2026  
**Audited Commit:** `22bbbb2c47f3f2b78c1b134590baf41383fd354f`  
**Contract:** `src/PuppyRaffle.sol`  
**Methodology:** Patrick Collins - 8 Phases  

---

## Executive Summary

A comprehensive security audit was conducted on the **PuppyRaffle** smart contract, a raffle protocol where participants send ETH to enter a drawing for a randomly generated puppy NFT. The audit followed Patrick Collins' 8-phase methodology and included static analysis (Slither, Aderyn), line-by-line manual review, and development of 7 Proof of Concept exploits.

### Contract Statistics

| Metric | Value |
|--------|-------|
| nSLOC | 143 |
| Complexity Score | 111 |
| Solidity Version | 0.7.6 |
| Test Coverage | 84% lines |

### Finding Summary

| Severity | Count | IDs |
|----------|-------|-----|
| HIGH | 7 | H-1 through H-7 |
| MEDIUM | 2 | M-1, M-2 |
| LOW | 4 | L-1 through L-4 |

---

## HIGH Severity Findings

---

### [H-1] Checks-Effects-Interactions Pattern Violation in `refund()` Enables Reentrancy

**Severity:** High  
**Location:** `src/PuppyRaffle.sol:96-105`

**Description:**
The `refund()` function sends ETH to the caller BEFORE updating the contract state (`players[playerIndex] = address(0)`). This violates the Checks-Effects-Interactions pattern, which is a known reentrancy vulnerability.

**Vulnerable Code:**
```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    payable(msg.sender).sendValue(entranceFee);  // External call FIRST

    players[playerIndex] = address(0);            // State update AFTER
    emit RaffleRefunded(playerAddress);
}

Impact:

    If sendValue() is ever replaced with .call{}(), an attacker can drain all ETH from the contract.

    Even with 2300 gas, the attacker's receive() function executes before the state update, violating CEI.

Proof of Concept:
PuppyRaffleExploits.t.sol: testPoCReentrancyRefund() and testPoCReentrancyWithoutGasLimit()

Recommended Mitigation:
diff

-    payable(msg.sender).sendValue(entranceFee);
-
-    players[playerIndex] = address(0);
-    emit RaffleRefunded(playerAddress);
+    players[playerIndex] = address(0);
+    emit RaffleRefunded(playerAddress);
+
+    payable(msg.sender).sendValue(entranceFee);

References:

    Solidity Docs: Checks-Effects-Interactions

    SWC-107: Reentrancy

[H-2] Denial of Service via Gas Exhaustion in Nested Loop

Severity: High
Location: src/PuppyRaffle.sol:86-91

Description:
The duplicate address check in enterRaffle() uses an O(n^2) nested loop. With approximately 200 players, a single enterRaffle() call exceeds the block gas limit, permanently preventing new players from entering.

Vulnerable Code:
solidity

for (uint256 i = 0; i < players.length - 1; i++) {
    for (uint256 j = i + 1; j < players.length; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}

Impact:

    An attacker fills the array with ~150-200 addresses.

    No one can enter the raffle afterward.

    The raffle is permanently bricked.

Proof of Concept:
PuppyRaffleExploits.t.sol: testPoCDoSGasNestedLoop() (100 players = >3M gas)

Recommended Mitigation:
diff

+ mapping(address => bool) private isPlayer;

  function enterRaffle(address[] memory newPlayers) public payable {
      require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
      for (uint256 i = 0; i < newPlayers.length; i++) {
+         require(!isPlayer[newPlayers[i]], "PuppyRaffle: Duplicate player");
+         isPlayer[newPlayers[i]] = true;
          players.push(newPlayers[i]);
      }
-     for (uint256 i = 0; i < players.length - 1; i++) {
-         for (uint256 j = i + 1; j < players.length; j++) {
-             require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-         }
-     }
      emit RaffleEnter(newPlayers);
  }

References:

    SWC-128: DoS with Block Gas Limit

[H-3] Winner Can Be address(0), Causing Permanent Loss of Funds and NFT

Severity: High
Location: src/PuppyRaffle.sol:125-154

Description:
selectWinner() does not check whether the selected winner is address(0). If a player refunds before winner selection, their position becomes address(0). If selected, ETH and NFT are sent to address(0), burning them forever.

Vulnerable Code:
solidity

address winner = players[winnerIndex];  // Can be address(0)
// ...
(bool success,) = winner.call{value: prizePool}("");
_safeMint(winner, tokenId);

Impact:

    Prize ETH is burned forever.

    NFT is minted to address(0) and lost forever.

    The raffle is permanently locked.

Proof of Concept:
PuppyRaffleExploits.t.sol: testPoCWinnerIsAddressZero()

Recommended Mitigation:
diff

+ uint256 validPlayersCount;
+ for (uint256 i = 0; i < players.length; i++) {
+     if (players[i] != address(0)) {
+         validPlayersCount++;
+     }
+ }

- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 totalAmountCollected = validPlayersCount * entranceFee;

  // When selecting winner
+ require(winner != address(0), "PuppyRaffle: Invalid winner");

[H-4] Incorrect Prize Calculation When Refunds Occur

Severity: High
Location: src/PuppyRaffle.sol:131-133

Description:
selectWinner() calculates totalAmountCollected = players.length * entranceFee, assuming all players paid. After refunds, the contract holds less ETH than calculated, causing the transfer to fail.

Vulnerable Code:
solidity

uint256 totalAmountCollected = players.length * entranceFee;
uint256 prizePool = (totalAmountCollected * 80) / 100;
uint256 fee = (totalAmountCollected * 20) / 100;

Impact:

    selectWinner() reverts due to insufficient ETH.

    The raffle is permanently locked.

Proof of Concept:
PuppyRaffleExploits.t.sol: testPoCPrizeCalculationBrokenByRefunds()

Recommended Mitigation:
diff

- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 activePlayers;
+ for (uint256 i = 0; i < players.length; i++) {
+     if (players[i] != address(0)) {
+         activePlayers++;
+     }
+ }
+ uint256 totalAmountCollected = activePlayers * entranceFee;

[H-5] withdrawFees() Has No Access Control

Severity: High
Location: src/PuppyRaffle.sol:157

Description:
The withdrawFees() function has no access control modifier. Anyone can call it after a winner is selected.

Vulnerable Code:
solidity

function withdrawFees() external {

Impact:

    A malicious actor can force fee withdrawals at any time.

Recommended Mitigation:
diff

- function withdrawFees() external {
+ function withdrawFees() external onlyOwner {

[H-6] Denial of Service on withdrawFees() via Strict Balance Equality

Severity: High
Location: src/PuppyRaffle.sol:158

Description:
withdrawFees() uses strict equality (==) to compare the contract balance with totalFees. Anyone can force-send 1 wei via selfdestruct, permanently breaking the equality check.

Vulnerable Code:
solidity

require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

Impact:

    Fees are permanently locked.

    Attack costs only 1 wei.

Proof of Concept:
PuppyRaffleExploits.t.sol: testPoCDoSWithOneWei()

Recommended Mitigation:
diff

- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
+ require(address(this).balance >= uint256(totalFees), "PuppyRaffle: Insufficient balance for fees");

References:

    SWC-132: Unexpected Ether Balance

    Force-feeding ETH via selfdestruct

[H-7] Predictable and Manipulable Randomness in selectWinner()

Severity: High
Location: src/PuppyRaffle.sol:128-129

Description:
The winner index is generated using keccak256 of predictable values (msg.sender, block.timestamp, block.difficulty). Miners can manipulate block.timestamp and MEV bots can simulate results before submitting.

Vulnerable Code:
solidity

uint256 winnerIndex =
    uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;

Impact:

    Miner/validator can influence the winner.

    Attacker can simulate and only execute if they win.

Recommended Mitigation:
Use Chainlink VRF for verifiable randomness.

References:

    Chainlink VRF Documentation

    SWC-120: Weak Sources of Randomness

MEDIUM Severity Findings
[M-1] Duplicate Check Bypassed Using refund()

Severity: Medium
Location: src/PuppyRaffle.sol:86-91

Description:
After a refund, the player's position becomes address(0). The duplicate check does not consider address(0) as a duplicate. A player can re-enter after refund, appearing twice.

Proof of Concept:
PuppyRaffleExploits.t.sol: testPoCBypassDuplicateCheck()

Recommended Mitigation:
Use a mapping to track active participants (see H-2).
[M-2] getActivePlayerIndex() Returns Ambiguous 0

Severity: Medium
Location: src/PuppyRaffle.sol:110-117

Description:
Returns 0 for both "player at index 0" and "player not found".

Recommended Mitigation:
diff

- function getActivePlayerIndex(address player) external view returns (uint256) {
+ function getActivePlayerIndex(address player) external view returns (int256) {
      for (uint256 i = 0; i < players.length; i++) {
          if (players[i] == player) {
-             return i;
+             return int256(i);
          }
      }
-     return 0;
+     return -1;
  }

LOW Severity Findings
[L-1] Missing Zero-Address Check on feeAddress

Severity: Low
Location: src/PuppyRaffle.sol:62, 168

Recommended Mitigation:
diff

  constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) {
+     require(_feeAddress != address(0), "PuppyRaffle: Invalid fee address");
      // ...
  }

  function changeFeeAddress(address newFeeAddress) external onlyOwner {
+     require(newFeeAddress != address(0), "PuppyRaffle: Invalid fee address");
      feeAddress = newFeeAddress;
  }

[L-2] _isActivePlayer() Is Dead Code

Severity: Low
Location: src/PuppyRaffle.sol:173-180

Recommended Mitigation:
Remove the unused function.
[L-3] State Variables Should Be constant or immutable

Severity: Low
Location: src/PuppyRaffle.sol:24, 38, 43, 48

Recommended Mitigation:
diff

- uint256 public raffleDuration;
+ uint256 public immutable raffleDuration;

- string private commonImageUri = "ipfs://...";
+ string private constant COMMON_IMAGE_URI = "ipfs://...";

[L-4] Events Missing indexed Parameters

Severity: Low
Location: src/PuppyRaffle.sol:53-55

Recommended Mitigation:
diff

- event RaffleRefunded(address player);
+ event RaffleRefunded(address indexed player);

- event FeeAddressChanged(address newFeeAddress);
+ event FeeAddressChanged(address indexed newFeeAddress);

Mitigation Summary
ID	Vulnerability	Key Mitigation
H-1	Reentrancy in refund()	Move state update before ETH transfer
H-2	DoS via gas in loop	Use mapping instead of nested loop
H-3	Winner can be address(0)	Check winner != address(0)
H-4	Incorrect prize calculation	Count only active players
H-5	withdrawFees() no access control	Add onlyOwner modifier
H-6	DoS via strict equality	Use >= instead of ==
H-7	Weak randomness	Use Chainlink VRF
M-1	Duplicate check bypass	Use mapping (see H-2)
M-2	Ambiguous return value	Return int256 with -1 for not found
L-1	Missing zero-address check	Add require statement
L-2	Dead code	Remove _isActivePlayer()
L-3	Non-constant variables	Add constant/immutable
L-4	Events missing indexed	Add indexed keyword
Disclaimer

This audit was conducted for educational and portfolio purposes. It does not constitute a professional security audit for production deployment. The original code was created for the CodeHawks First Flight #2 contest in October 2023.
