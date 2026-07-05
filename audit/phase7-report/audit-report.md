## HIGH Severity Findings

---

### [H-1] Checks-Effects-Interactions Pattern Violation in refund()

**Severity:** High  
**Location:** src/PuppyRaffle.sol:96-105

**Description:**
The refund() function sends ETH to the caller BEFORE updating the contract state (players[playerIndex] = address(0)). This violates the Checks-Effects-Interactions pattern, which is a known reentrancy vulnerability.

**Vulnerable Code:**
```solidity
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded");

    payable(msg.sender).sendValue(entranceFee);  // External call FIRST

    players[playerIndex] = address(0);            // State update AFTER
    emit RaffleRefunded(playerAddress);
}
```

**Impact:**
- If sendValue() is ever replaced with .call{}(), an attacker can drain all ETH from the contract.
- Even with 2300 gas, the attacker's receive() function executes before the state update.

**Proof of Concept:**
PuppyRaffleExploits.t.sol: testPoCReentrancyRefund() and testPoCReentrancyWithoutGasLimit()

**Recommended Mitigation:**
```diff
-    payable(msg.sender).sendValue(entranceFee);
-
-    players[playerIndex] = address(0);
-    emit RaffleRefunded(playerAddress);
+    players[playerIndex] = address(0);
+    emit RaffleRefunded(playerAddress);
+
+    payable(msg.sender).sendValue(entranceFee);
```

**References:**
- [Solidity Docs: Checks-Effects-Interactions](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107)

---
### [H-2] Denial of Service via Gas Exhaustion in Nested Loop

**Severity:** High  
**Location:** src/PuppyRaffle.sol:86-91

**Description:**
The duplicate address check in enterRaffle() uses an O(n^2) nested loop. With approximately 200 players, a single enterRaffle() call exceeds the block gas limit, permanently preventing new players from entering.

**Vulnerable Code:**
```solidity
for (uint256 i = 0; i < players.length - 1; i++) {
    for (uint256 j = i + 1; j < players.length; j++) {
        require(players[i] != players[j], "PuppyRaffle: Duplicate player");
    }
}
```

**Impact:**
- An attacker fills the array with ~150-200 addresses paying the entrance fee.
- After that, NO ONE can enter the raffle.
- The raffle is permanently bricked.

**Proof of Concept:**
PuppyRaffleExploits.t.sol: testPoCDoSGasNestedLoop() - 100 players consume over 3 million gas.

**Recommended Mitigation:**
```diff
+ mapping(address => bool) private isPlayer;

  function enterRaffle(address[] memory newPlayers) public payable {
      require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough");
      for (uint256 i = 0; i < newPlayers.length; i++) {
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
```

**References:**
- [SWC-128: DoS with Block Gas Limit](https://swcregistry.io/docs/SWC-128)

---
### [H-3] Winner Can Be address(0), Causing Permanent Loss of Funds and NFT

**Severity:** High  
**Location:** src/PuppyRaffle.sol:125-154

**Description:**
selectWinner() does not check whether the selected winner is address(0). If a player requests a refund before the winner is selected, their position in the array becomes address(0). If the "random" index points to that position, ETH and the NFT are sent to address(0), burning them forever.

**Vulnerable Code:**
```solidity
address winner = players[winnerIndex];  // Can be address(0)
// ...
(bool success,) = winner.call{value: prizePool}("");
_safeMint(winner, tokenId);
```

**Impact:**
- Prize ETH is burned forever.
- NFT is minted to address(0) and lost forever.
- Legitimate players lose their money with no recovery possible.

**Proof of Concept:**
PuppyRaffleExploits.t.sol: testPoCWinnerIsAddressZero() demonstrates that selectWinner() reverts when attempting to send ETH to address(0).

**Recommended Mitigation:**
```diff
+ uint256 validPlayersCount;
+ for (uint256 i = 0; i < players.length; i++) {
+     if (players[i] != address(0)) {
+         validPlayersCount++;
+     }
+ }

- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 totalAmountCollected = validPlayersCount * entranceFee;

  // When selecting winner, ensure it is not address(0)
+ require(winner != address(0), "PuppyRaffle: Invalid winner");
```

---

### [H-4] Incorrect Prize Calculation When Refunds Occur

**Severity:** High  
**Location:** src/PuppyRaffle.sol:131-133

**Description:**
selectWinner() calculates totalAmountCollected = players.length * entranceFee, assuming all players in the array paid the fee. However, if some players requested refunds, their positions are address(0) and the contract no longer holds their ETH. The contract attempts to pay out more ETH than it actually holds.

**Vulnerable Code:**
```solidity
uint256 totalAmountCollected = players.length * entranceFee;
uint256 prizePool = (totalAmountCollected * 80) / 100;
uint256 fee = (totalAmountCollected * 20) / 100;
```

**Impact:**
- selectWinner() reverts because the contract does not have enough ETH.
- The legitimate winner cannot receive their prize.
- The raffle is permanently locked.

**Proof of Concept:**
PuppyRaffleExploits.t.sol: testPoCPrizeCalculationBrokenByRefunds() demonstrates that with 4 players and 2 refunds, selectWinner() fails because it attempts to send 3.2 ETH when only 2 ETH exist.

**Recommended Mitigation:**
```diff
- uint256 totalAmountCollected = players.length * entranceFee;
+ uint256 activePlayers;
+ for (uint256 i = 0; i < players.length; i++) {
+     if (players[i] != address(0)) {
+         activePlayers++;
+     }
+ }
+ uint256 totalAmountCollected = activePlayers * entranceFee;
```

---
### [H-5] withdrawFees() Has No Access Control

**Severity:** High  
**Location:** src/PuppyRaffle.sol:157

**Description:**
The withdrawFees() function is external with no access control modifier. Anyone can call it after a winner is selected. Although the funds go to feeAddress, this allows a malicious third party to force fee withdrawals at inopportune times.

**Vulnerable Code:**
```solidity
function withdrawFees() external {  // Anyone can call this
```

**Impact:**
- A malicious actor can force fee withdrawals immediately after selectWinner().
- May interfere with protocol accounting.

**Recommended Mitigation:**
```diff
- function withdrawFees() external {
+ function withdrawFees() external onlyOwner {
```

---

### [H-6] Denial of Service on withdrawFees() via Strict Balance Equality

**Severity:** High  
**Location:** src/PuppyRaffle.sol:158

**Description:**
withdrawFees() uses strict equality (==) to compare the contract balance with totalFees. If anyone sends 1 wei to the contract via selfdestruct(), the balance will never again be exactly equal to totalFees, permanently locking the function.

**Vulnerable Code:**
```solidity
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active");
```

**Impact:**
- Fees are permanently locked.
- There is no way to recover the funds.
- The attack costs only 1 wei.

**Proof of Concept:**
PuppyRaffleExploits.t.sol: testPoCDoSWithOneWei() demonstrates that after a selfdestruct with 1 wei, withdrawFees() permanently reverts.

**Recommended Mitigation:**
```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active");
+ require(address(this).balance >= uint256(totalFees), "PuppyRaffle: Insufficient balance for fees");
```

**References:**
- [SWC-132: Unexpected Ether Balance](https://swcregistry.io/docs/SWC-132)
- [Force-feeding ETH via selfdestruct](https://consensys.github.io/smart-contract-best-practices/attacks/force-feeding/)

---

### [H-7] Predictable and Manipulable Randomness in selectWinner()

**Severity:** High  
**Location:** src/PuppyRaffle.sol:128-129

**Description:**
The contract generates the winner index using keccak256 of predictable and manipulable values: msg.sender, block.timestamp, and block.difficulty. A miner can manipulate block.timestamp within a range, and an MEV bot can simulate the result before submitting a transaction.

**Vulnerable Code:**
```solidity
uint256 winnerIndex =
    uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length;
```

**Impact:**
- A miner/validator can influence who wins.
- An attacker can simulate the result and only execute if they win.
- The "randomness" is not random at all.

**Recommended Mitigation:**
Use a verifiable randomness oracle such as Chainlink VRF:
```solidity
import {VRFConsumerBase} from "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

function requestRandomWinner() external {
    requestRandomness(keyHash, fee);
}

function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
    uint256 winnerIndex = randomness % players.length;
    // ...
}
```

**References:**
- [Chainlink VRF Documentation](https://docs.chain.link/vrf)
- [SWC-120: Weak Sources of Randomness](https://swcregistry.io/docs/SWC-120)

---
