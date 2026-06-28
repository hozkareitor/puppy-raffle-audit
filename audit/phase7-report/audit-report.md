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
| 🔴 HIGH | 7 | H-1 through H-7 |
| 🟡 MEDIUM | 2 | M-1, M-2 |
| 🟢 LOW | 4 | L-1 through L-4 |

---

## HIGH Severity Findings

---

### [H-1] Checks-Effects-Interactions Pattern Violation in `refund()` Enables Reentrancy

**Severity:** High  
**Location:** `src/PuppyRaffle.sol:96-105`

**Description:**
The `refund()` function sends ETH to the caller BEFORE updating the contract state (`players[playerIndex] = address(0)`). This violates the Checks-Effects-Interactions pattern, which is a known reentrancy vulnerability. Although OpenZeppelin's `sendValue()` limits forwarded gas to 2300, any future change to `.call{}()` would make the attack devastating. Even with 2300 gas, an attacker can execute code (such as storage writes) before the state is updated.

```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    payable(msg.sender).sendValue(entranceFee);  // ← External call FIRST

    players[playerIndex] = address(0);            // ← State update AFTER
    emit RaffleRefunded(playerAddress);
}

Impact:

    If sendValue() is ever replaced with .call{}(), an attacker can drain all ETH from the contract.

    Even with 2300 gas, the attacker's receive() function executes before the state update.

Proof of Concept:
The testPoCReentrancyRefund() test in PuppyRaffleExploits.t.sol demonstrates that the attacker's receive() executes BEFORE players[playerIndex] is set to address(0). The testPoCReentrancyWithoutGasLimit() test demonstrates full contract drainage when .call{}() is used.

Recommended Mitigation:
diff

function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+   players[playerIndex] = address(0);
+   emit RaffleRefunded(playerAddress);

    payable(msg.sender).sendValue(entranceFee);
-
-   players[playerIndex] = address(0);
-   emit RaffleRefunded(playerAddress);
}

References:

    Solidity Docs: Checks-Effects-Interactions

    SWC-107: Reentrancy

[H-2] Denial of Service via Gas Exhaustion in Nested Loop in enterRaffle()

Severity: High
Location: src/PuppyRaffle.sol:86-91

Description:
The duplicate address check in enterRaffle() uses an O(n²) nested loop that iterates over the entire players[] array. As more players enter, the gas required grows quadratically. With approximately 200 players, a single enterRaffle() call exceeds the block gas limit, permanently preventing new players from entering.
solidity

for (uint256 i = 0; i < players.length - 1; i++) {
    for (uint256 j = i + 1; j < players.length; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}

Impact:

    An attacker can fill the array with ~150-200 addresses (paying the entrance fee).

    Afterward, NO ONE can enter the raffle.

    The raffle is permanently bricked.

Proof of Concept:
The testPoCDoSGasNestedLoop() test demonstrates that with 100 players, a single entry consumes over 3 million gas. With 200 players, it would exceed 15 million gas (block limit).

Recommended Mitigation:
diff

+ mapping(address => bool) private isPlayer;

function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    for (uint256 i = 0; i < newPlayers.length; i++) {
+       require(!isPlayer[newPlayers[i]], "PuppyRaffle: Duplicate player");
+       isPlayer[newPlayers[i]] = true;
        players.push(newPlayers[i]);
    }
-
-   for (uint256 i = 0; i < players.length - 1; i++) {
-       for (uint256 j = i + 1; j < players.length; j++) {
-           require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-       }
-   }
    emit RaffleEnter(newPlayers);
}

References:

    SWC-128: DoS with Block Gas Limit

[H-3] Winner Can Be address(0), Causing Permanent Loss of Funds and NFT

Severity: High
Location: src/PuppyRaffle.sol:125-154

Description:
selectWinner() does not check whether the selected winner is address(0). If a player requests a refund before the winner is selected, their position in the array becomes address(0). If the "random" index points to that position, ETH and the NFT are sent to address(0), burning them forever.
solidity

address winner = players[winnerIndex];  // ← Can be address(0)
// ...
(bool success,) = winner.call{value: prizePool}("");  // ← ETH to address(0)
_safeMint(winner, tokenId);  // ← NFT to address(0)

Impact:

    Prize ETH is burned forever.

    NFT is minted to address(0) and lost forever.

    Legitimate players lose their money with no recovery possible.

Proof of Concept:
The testPoCWinnerIsAddressZero() test demonstrates that selectWinner() reverts when attempting to send ETH to address(0), permanently locking the raffle.

Recommended Mitigation:
diff

+ uint256 validPlayersCount = 0;
+ for (uint256 i = 0; i < players.length; i++) {
+     if (players[i] != address(0)) {
+         validPlayersCount++;
+     }
+ }

- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 totalAmountCollected = validPlayersCount * entranceFee;

// When selecting winner, ensure it is not address(0)
+ require(winner != address(0), "PuppyRaffle: Invalid winner");

[H-4] Incorrect Prize Calculation When Refunds Occur

Severity: High
Location: src/PuppyRaffle.sol:131-133

Description:
selectWinner() calculates totalAmountCollected = players.length * entranceFee, assuming all players in the array paid the fee. However, if some players requested refunds, their positions are address(0) and the contract no longer holds their ETH. The contract attempts to pay out more ETH than it actually holds.
solidity

uint256 totalAmountCollected = players.length * entranceFee;
uint256 prizePool = (totalAmountCollected * 80) / 100;
uint256 fee = (totalAmountCollected * 20) / 100;

Impact:

    selectWinner() reverts because the contract does not have enough ETH.

    The legitimate winner cannot receive their prize.

    The raffle is permanently locked.

Proof of Concept:
The testPoCPrizeCalculationBrokenByRefunds() test demonstrates that with 4 players and 2 refunds, selectWinner() fails because it attempts to send 3.2 ETH when only 2 ETH exist.

Recommended Mitigation:
diff

- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 activePlayers = 0;
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
The withdrawFees() function is external with no access control modifier. Anyone can call it after a winner is selected. Although the funds go to feeAddress, this allows a malicious third party to force fee withdrawals at inopportune times.
solidity

function withdrawFees() external {  // ← Anyone can call!

Impact:

    A malicious actor can force fee withdrawals immediately after selectWinner().

    May interfere with protocol accounting.

Recommended Mitigation:
diff

- function withdrawFees() external {
+ function withdrawFees() external onlyOwner {

[H-6] Denial of Service on withdrawFees() via Strict Balance Equality

Severity: High
Location: src/PuppyRaffle.sol:158

Description:
withdrawFees() uses strict equality (==) to compare the contract balance with totalFees. If anyone sends 1 wei to the contract via selfdestruct(), the balance will never again be exactly equal to totalFees, permanently locking the function.
solidity

require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");

Impact:

    Fees are permanently locked.

    There is no way to recover the funds.

    The attack costs only 1 wei.

Proof of Concept:
The testPoCDoSWithOneWei() test demonstrates that after a selfdestruct with 1 wei, withdrawFees() permanently reverts.

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
The contract generates the winner index using keccak256 of predictable and manipulable values: msg.sender, block.timestamp, and block.difficulty. A miner can manipulate block.timestamp within a range, and an MEV bot can simulate the result before submitting a transaction.
solidity

uint256 winnerIndex =
    uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;

Impact:

    A miner/validator can influence who wins.

    An attacker can simulate the result and only execute if they win.

    The "randomness" is not random at all.

Recommended Mitigation:
Use a verifiable randomness oracle such as Chainlink VRF:
solidity

import {VRFConsumerBase} from "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

function requestRandomWinner() external {
    requestRandomness(keyHash, fee);
}

function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
    uint256 winnerIndex = randomness % players.length;
    // ...
}

References:

    Chainlink VRF Documentation

    SWC-120: Weak Sources of Randomness

MEDIUM Severity Findings
[M-1] Duplicate Check Can Be Bypassed Using refund()

Severity: Medium
Location: src/PuppyRaffle.sol:86-91

Description:
When a player requests a refund, their position becomes address(0). The duplicate check does not consider address(0) as a duplicate of any real address. Therefore, a player can re-enter after a refund, appearing twice in the array.

Impact:

    A player can have multiple entries in the raffle.

    This manipulates the odds in their favor.

Proof of Concept:
The testPoCBypassDuplicateCheck() test demonstrates that Alice can appear twice in the array after refund + re-enter.

Recommended Mitigation:
Use a mapping to track active participants (see H-2).
[M-2] getActivePlayerIndex() Returns 0 for Both "Not Found" and Index 0

Severity: Medium
Location: src/PuppyRaffle.sol:110-117

Description:
The function returns 0 in two different cases: when the player is at index 0 and when the player is not in the array. This is ambiguous and can cause errors in contracts that depend on this function.
solidity

function getActivePlayerIndex(address player) external view returns (uint256) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == player) {
            return i;
        }
    }
    return 0;  // ← Ambiguous: 0 = index 0 or not found
}

Impact:

    External contracts may misinterpret the result.

    Can lead to logic errors in integrations.

Recommended Mitigation:
diff

function getActivePlayerIndex(address player) external view returns (int256) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == player) {
-           return i;
+           return int256(i);
        }
    }
-   return 0;
+   return -1;  // Clearly "not found"
}

LOW Severity Findings
[L-1] Missing Zero-Address Check on feeAddress

Severity: Low
Location: src/PuppyRaffle.sol:62, 168

Description:
Neither the constructor nor changeFeeAddress() validates that _feeAddress is not address(0). If set to address(0), all fees will be burned.

Recommended Mitigation:
diff

constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) {
+   require(_feeAddress != address(0), "PuppyRaffle: Invalid fee address");
    // ...
}

function changeFeeAddress(address newFeeAddress) external onlyOwner {
+   require(newFeeAddress != address(0), "PuppyRaffle: Invalid fee address");
    feeAddress = newFeeAddress;
}

[L-2] _isActivePlayer() Is Dead Code

Severity: Low
Location: src/PuppyRaffle.sol:173-180

Description:
The _isActivePlayer() function is defined but never used anywhere in the contract. This wastes deployment gas and increases the attack surface.

Recommended Mitigation:
Remove the function or use it where appropriate.
[L-3] State Variables Should Be constant or immutable

Severity: Low
Location: src/PuppyRaffle.sol:24, 38, 43, 48

Description:
raffleDuration should be immutable, and the image URIs (commonImageUri, rareImageUri, legendaryImageUri) should be constant to save gas.

Recommended Mitigation:
diff

- uint256 public raffleDuration;
+ uint256 public immutable raffleDuration;

- string private commonImageUri = "ipfs://...";
+ string private constant COMMON_IMAGE_URI = "ipfs://...";

[L-4] Events Missing indexed Parameters

Severity: Low
Location: src/PuppyRaffle.sol:53-55

Description:
The RaffleRefunded and FeeAddressChanged events have address parameters without the indexed modifier, making them harder to search for off-chain tools.

Recommended Mitigation:
diff

- event RaffleRefunded(address player);
+ event RaffleRefunded(address indexed player);

- event FeeAddressChanged(address newFeeAddress);
+ event FeeAddressChanged(address indexed newFeeAddress);

Mitigation Summary
ID	Vulnerability	Key Mitigation
H-1	Reentrancy in refund()	Move state update BEFORE ETH transfer
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
