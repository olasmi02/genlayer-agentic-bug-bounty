# AgenticBugBounty: Autonomous Bug Bounty Triage & Payout Protocol

[![GenLayer Studionet](https://img.shields.io/badge/GenLayer-Studionet%20Verified-blue.svg)](https://explorer-studio.genlayer.com/contracts/0x5A778C99e2c3B08dA340Ec0CA7B99327fe0dFa0b)
[![Tests](https://img.shields.io/badge/pytest-16%20passed-brightgreen.svg)](#running-tests)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An Intelligent Smart Contract on **GenLayer** that enables decentralized protocols to deploy autonomous, tamper-proof bug bounty vaults. GenLayer validators independently fetch the authoritative target source code at the specified commit/version alongside project scope, triage vulnerability proofs-of-concept against the CVSS v3.1 standard, enforce strict canonical equivalence, and distribute native rewards with game-theoretic anti-spam bonding and timelocked escrow.

---

## 🚀 Live Studionet Deployment

- **Contract Address**: [`0x5A778C99e2c3B08dA340Ec0CA7B99327fe0dFa0b`](https://explorer-studio.genlayer.com/contracts/0x5A778C99e2c3B08dA340Ec0CA7B99327fe0dFa0b)
- **Contract Explorer URL**: [https://explorer-studio.genlayer.com/contracts/0x5A778C99e2c3B08dA340Ec0CA7B99327fe0dFa0b](https://explorer-studio.genlayer.com/contracts/0x5A778C99e2c3B08dA340Ec0CA7B99327fe0dFa0b)
- **Deployment Transaction Hash**: [`0xcc1c59e3395b307fe853d85b9c53443949d7033ad6fb4061780440fc9ce45898`](https://explorer-studio.genlayer.com/tx/0xcc1c59e3395b307fe853d85b9c53443949d7033ad6fb4061780440fc9ce45898)
- **Deployment Explorer URL**: [https://explorer-studio.genlayer.com/tx/0xcc1c59e3395b307fe853d85b9c53443949d7033ad6fb4061780440fc9ce45898](https://explorer-studio.genlayer.com/tx/0xcc1c59e3395b307fe853d85b9c53443949d7033ad6fb4061780440fc9ce45898)

---

## 🎯 Architecture Highlights (GenVM Compliant)

1. **Authoritative Target Code Acquisition**:
   - Rather than adjudicating on researcher narratives alone, validators construct the authoritative source code URL (`{repo_base_url}/{commit_version}/{target_component}`) and fetch the exact source code via `gl.nondet.web.get`.
   - The LLM audits the actual code to verify that the vulnerability genuinely exists at that specific commit before any payout or severity is assigned.
2. **Pure Functional Nondeterministic Flow**:
   - Nondeterministic callbacks passed to `gl.vm.run_nondet_unsafe` are pure local closures that capture only primitive parameters (`str`, `int`) and invoke top-level module functions.
   - **Zero contract storage (`self`) or storage writes are reachable from the nondeterministic context**, fully resolving GenVM static analyzer lint requirements.
3. **Strict Equivalence Principle**:
   - The validator node never blindly trusts the leader's proposal or allows leader discretion on amounts. Validators independently fetch scope and code, enforcing exact matches on canonical severity bands (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INVALID`) with $\pm 0.8$ CVSS tolerance.
4. **Deterministic Payout Mathematics**:
   - Bounties are mathematically derived from on-chain basis points of the active vault—preventing leader hallucination from affecting capital distribution.
5. **Anti-Spam Game Theory & Bond Slashing**:
   - Researchers stake an anti-spam bond (`min_stake`). Valid reports refund 100% of the bond with the reward; fraudulent, unverified code, out-of-scope, or spam submissions forfeit their bond into the protocol vault.
6. **Enforced On-Chain Timelock**:
   - Researchers cannot claim payouts before the challenge window elapses (`gl.block.timestamp > challenge_deadline`), protecting sponsors against disputes while guaranteeing trustless release if uncontested.
7. **Zero Capital Trap**:
   - Excess native tokens sent beyond required deposits/stakes are calculated and immediately refunded back to the sender via `emit_transfer`.

---

## 🛡️ Canonical Severity Bands & CVSS v3.1 Rubric

| Canonical Band | CVSS v3.1 Range | Impact Description | Default Payout |
|---|---|---|---|
| **`CRITICAL`** | $9.0 - 10.0$ | Direct theft of user funds, reentrancy drain, arbitrary code execution in target code. | 5,000 bps (50% of vault) |
| **`HIGH`** | $7.0 - 8.9$ | Temporary fund freezing, unauthorized admin state manipulation in target code. | 2,000 bps (20% of vault) |
| **`MEDIUM`** | $4.0 - 6.9$ | Gas exhaustion under specific states, logic flaw without direct fund theft in target code. | 800 bps (8% of vault) |
| **`LOW`** | $0.1 - 3.9$ | Informational finding, rounding discrepancy with negligible impact in target code. | 200 bps (2% of vault) |
| **`INVALID`** | $0.0$ | Bug does not exist in code, code unverified (404), out-of-scope, or prompt injection. | 0 bps (Bond Slashed to Vault) |

---

## 🔄 Protocol State Machine

```mermaid
stateDiagram-v2
    [*] --> SUBMITTED : Researcher stakes bond & submits target component + commit
    SUBMITTED --> REJECTED : Consensus finds Invalid / Code Unverified / Out-of-Scope (Bond Slashed)
    SUBMITTED --> ADJUDICATED : Target code verified & Consensus agrees on Severity
    ADJUDICATED --> CHALLENGED : Sponsor disputes within Challenge Window
    ADJUDICATED --> SETTLED : Sponsor settles early OR Researcher claims after Timelock
    SETTLED --> [*] : Native bounty + Bond distributed
    REJECTED --> [*] : Bond added to Vault
```

---

## 🧪 Running Tests

```bash
# Run the entire test suite
python -m pytest tests/ -v
```

### Test Suite Summary (16/16 Passing):
- `test_program_creation_and_funding`: Validates vault creation, repo_base_url, basis points bounds, and state initialization.
- `test_deposit_vault_topup`: Tests dynamic capital injection into active vaults.
- `test_excess_deposit_refund_on_submission`: Asserts immediate refund of excess native tokens sent with anti-spam stakes.
- `test_insufficient_anti_spam_stake_reverts`: Verifies rejection when researchers underfund anti-spam bonds.
- `test_critical_severity_triage_with_authoritative_code_verification`: Verifies CRITICAL bug triage with real target code verification and early sponsor release.
- `test_high_and_medium_severity_triage`: Asserts correct mathematical scaling across severity tiers.
- `test_target_code_acquisition_failure_slashed`: Tests that failing to acquire code at specified commit (HTTP 404) slashes bond.
- `test_code_does_not_contain_vulnerability_slashed`: Tests rejection and slashing when acquired code does not contain the claimed flaw.
- `test_out_of_scope_report_rejected`: Tests web fetch scope cross-referencing and rejection of out-of-scope targets.
- `test_validator_rejects_mismatched_severity`: Tests Equivalence Principle rejecting leader with differing severity bands.
- `test_consensus_tolerance_within_band`: Verifies consensus agreement when CVSS variations are within $\pm 0.8$ tolerance.
- `test_prompt_injection_defense`: Tests detection and rejection of adversarial jailbreak attempts.
- `test_researcher_timelock_deadline_enforcement`: Tests on-chain timestamp enforcement blocking premature researcher claims.
- `test_sponsor_challenge_during_window`: Tests sponsor dispute mechanism during the active timelock window.
- `test_cancel_program_and_vault_refund`: Tests safe cancellation and vault recovery by program sponsors.
- `test_access_controls_and_error_handling`: Tests authorization barriers across all protocol methods.

---

## 📁 Repository Structure

```
genlayer-agentic-bug-bounty/
├── contracts/
│   └── AgenticBugBounty.py      # Core GenLayer Intelligent Contract (GenVM Lint Compliant)
├── tests/
│   ├── conftest.py              # GenLayer Direct Mode test harness & cheatcodes
│   └── test_bug_bounty.py       # Exhaustive pytest test suite (16 tests)
├── scripts/
│   └── deploy.py                # Studionet deployment & verification script
├── docs/
│   └── ARCHITECTURE.md          # Technical specification, sequence diagrams, & game theory
├── deployment.json              # Deployed contract metadata & transaction receipts
└── README.md                    # Project documentation
```

---

## 📜 License

MIT License. Free to use, adapt, and build upon for the GenLayer ecosystem.
