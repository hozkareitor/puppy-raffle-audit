# Puppy Raffle - Smart Contract Security Audit

**Auditor:** [@hozkareitor](https://github.com/hozkareitor)  
**Date:** June 2026  
**Methodology:** Patrick Collins - 8 Phases  
**Platform:** CodeHawks First Flight #2  
**Original Contest:** October 2023

---

## Executive Summary

Comprehensive security audit of the **PuppyRaffle** smart contract, a raffle protocol where participants send ETH to enter a drawing for a randomly generated puppy NFT.

| Metric | Value |
|--------|-------|
| nSLOC | 143 |
| Complexity Score | 111 |
| Solidity Version | 0.7.6 |
| Deployment Chain | Ethereum |
| Test Coverage | 84% lines |

---

## Repository Structure

.
├── README.md ← Audit portfolio overview
├── audit/ ← Audit documentation by phase
│ ├── phase1-scoping/ ← Scope definition & protocol understanding
│ ├── phase2-recon/ ← Architecture & flow diagrams
│ ├── phase3-tools/ ← Slither, Aderyn, Forge coverage
│ ├── phase4-vulnerabilities/ ← Vulnerability identification
│ ├── phase5-exploits/ ← Proof of Code
│ ├── phase6-report/ ← Final audit report
│ ├── phase7-remediation/ ← Fix recommendations
│ └── phase8-delivery/ ← Final delivery package
├── src/ ← Original audited code
│ └── PuppyRaffle.sol
├── test/ ← Original test suite
│ └── PuppyRaffleTest.t.sol
└── foundry.toml
text


---

## Audit Methodology

Security audit based on **Patrick Collins' 8-phase methodology**:

| Phase | Objective | Status |
|-------|-----------|--------|
| **1. Scoping** | Understand WHAT is being audited | ✅ Complete |
| **2. Recon** | Understand HOW the protocol works | ✅ Complete |
| **3. Tools** | Automated analysis (Slither, Aderyn) | ✅ Complete |
| **4. Vulnerabilities** | Manual vulnerability identification | 🔄 In Progress |
| **5. Exploits** | Proof of Code development | ⬜ Pending |
| **6. Report** | Professional audit report | ⬜ Pending |
| **7. Remediation** | Fix recommendations | ⬜ Pending |
| **8. Delivery** | Final delivery | ⬜ Pending |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/hozkareitor/puppy-raffle-audit.git
cd puppy-raffle-audit

# Install dependencies
forge install

# Run original tests
forge test -vvv

# Run coverage
forge coverage

# Run static analysis
slither .
aderyn .

📊 Preliminary Findings
ID	Title	Severity	Status
H-1	Weak PRNG in selectWinner()	🔴 HIGH	Confirmed
H-2	Reentrancy in refund()	🔴 HIGH	Pending PoC
H-3	DoS via strict equality in withdrawFees()	🔴 HIGH	Confirmed
H-4	withdrawFees() has no access control	🔴 HIGH	Confirmed
M-1	abi.encodePacked() collision risk	🟡 MEDIUM	Confirmed
M-2	O(n²) DoS via gas exhaustion	🟡 MEDIUM	Confirmed
L-1	Missing zero-address check on feeAddress	🟢 LOW	Confirmed
L-2	_isActivePlayer() unused dead code	🟢 LOW	Confirmed
L-3	State variables should be constant/immutable	🟢 LOW	Confirmed

Disclaimer

This audit was conducted for educational and portfolio purposes. It does not constitute a professional security audit for production deployment. The original code was created for the CodeHawks First Flight #2 contest in October 2023.
Contact

    GitHub: @hozkareitor

    Email: hozkareitor@gmail.com
  
