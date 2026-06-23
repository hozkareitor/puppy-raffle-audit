# Phase 1: Scoping - Puppy Raffle

## Project Details
- **Commit Hash:** `22bbbb2c47f3f2b78c1b134590baf41383fd354f`
- **Contracts in Scope:** `./src/PuppyRaffle.sol`
- **nSLOC:** 143
- **Complexity Score:** 111
- **Solidity Version:** 0.7.6
- **Deployment Chain:** Ethereum Mainnet
- **Token Support:** ETH (native only)
- **Upgradeable:** No

## Protocol Summary
A raffle protocol where players pay ETH to enter. After a set duration, a winner is selected pseudo-randomly and receives:
- 80% of the total pot
- A randomly generated puppy NFT (Common/Rare/Legendary)

The remaining 20% goes to the `feeAddress` as protocol fees.

## Roles Identified

| Role | Privileges | Functions |
|------|------------|-----------|
| **Owner** | Protocol deployer | `changeFeeAddress(address)` |
| **Player** | Raffle participant | `enterRaffle(address[])`, `refund(uint256)` |

## External Dependencies

| Dependency | Version | Usage |
|------------|---------|-------|
| OpenZeppelin ERC721 | v3.4.0 | NFT base contract |
| OpenZeppelin Ownable | v3.4.0 | Access control (`onlyOwner`) |
| OpenZeppelin Address | v3.4.0 | Safe ETH transfers (`sendValue`) |
| Base64 (Brechtpd) | v1.1.0 | On-chain SVG/metadata encoding |

## Known Issues
None (as stated in README)
