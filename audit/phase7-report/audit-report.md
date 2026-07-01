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
