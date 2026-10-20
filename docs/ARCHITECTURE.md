# Architecture & Technical Specification: AgenticBugBounty

## 1. Executive Summary

`AgenticBugBounty` is a decentralized, autonomous bug bounty triage and payout protocol built natively on GenLayer. It replaces slow, costly, and centralized bug bounty intermediaries (such as Immunefi or HackerOne triage desks) with deterministic on-chain consensus executed by GenLayer Intelligent Validators.

Key Innovations:
- **Authoritative Target Code Acquisition**: Validators deterministically derive and fetch the referenced target source code at the specified commit/version (`code_url = {repo_base_url}/{commit}/{target_component}`) via `gl.nondet.web.get` before evaluating the vulnerability.
- **Autonomous Scope Verification**: Non-deterministic web fetch (`gl.nondet.web.get`) cross-references target files against live project `security.md` scopes.
- **Pure Functional Nondeterministic Flow (GenVM Compliant)**: Nondeterministic triage callbacks (`leader_fn` and `validator_fn`) are strictly pure closures capturing only local primitive arguments. No contract storage (`self`) or storage writes are reachable from the nondeterministic context.
- **Quarantined & Reserved Adjudicated Obligations**: Adjudicated payouts are immediately transferred from unreserved vault capital into a dedicated `reserved_payouts` pool, guaranteeing that subsequent reports or withdrawals cannot cause insolvency.
- **Complete, Bounded Challenge Lifecycle**:
  - Sponsors can challenge an adjudicated report during the challenge window.
  - Challenges are bounded by `challenge_resolution_deadline`.
  - Sponsors can resolve challenges via `resolve_challenge` (uphold and payout, or dismiss with bond refund or bond slashing).
  - If the sponsor fails to resolve the challenge within the bounded window, `claim_expired_challenge` executes default settlement to prevent indefinite lockups.
- **Insolvency Prevention for Active Reports**:
  - `cancel_program` and `withdraw_vault` strictly enforce `program.active_reports_count == 0` and `program.reserved_payouts == 0`.
  - Sponsors are barred from cancelling or withdrawing while any reports are submitted, adjudicated, or challenged.
- **Equivalence Principle with Canonical Severity Bands**: Leader nodes propose evaluations, but validators strictly enforce matching canonical severity bands (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INVALID`) and bounded CVSS score tolerances ($\pm 0.8$).
- **Anti-Spam Game Theory & Slashing**: Researchers stake a refundable bond (`min_stake`). Valid bugs refund 100% of the bond with the reward; unverified code, fraudulent, or spam reports are slashed directly into the project vault.

---

## 2. End-to-End Workflow & State Machine

```mermaid
sequenceDiagram
    autonumber
    actor Sponsor as Protocol Sponsor
    actor Researcher as Security Researcher
    participant Contract as AgenticBugBounty (GenLayer)
    participant Validators as GenLayer Validator Consensus
    participant GitWeb as Authoritative Repository (GitHub / Code Host)

    Sponsor->>Contract: create_program(name, repo_base_url, scope_url, min_stake, payouts) + [Vault Native Value]
    Note over Contract: Vault locked in escrow (unreserved balance)

    Researcher->>Contract: submit_report(target_component, commit_version, title, PoC) + [Anti-Spam Stake]
    Note over Contract: Anti-spam bond locked; excess refunded immediately<br/>active_reports_count incremented

    Contract->>Validators: triage_report(report_id)
    Note over Validators: Pure functional closure executes with local primitives (No storage reachable)
    Validators->>GitWeb: 1. gl.nondet.web.get(scope_url) -> Verify scope
    Validators->>GitWeb: 2. gl.nondet.web.get(code_url) -> Authoritative code at commit
    Validators->>Validators: 3. gl.nondet.exec_prompt(Target Code + PoC + CVSS Rubric)
    Validators->>Validators: 4. Equivalence check (Canonical Severity Band & Code Verification)
    Validators-->>Contract: Consensus Finalized (Severity, CVSS, CodeVerified, Summary)

    alt Report Invalid / Out-of-Scope / Code Unverified / Spam
        Note over Contract: Status -> REJECTED<br/>Anti-spam bond slashed into Vault<br/>active_reports_count decremented
    else Report Valid (LOW, MEDIUM, HIGH, CRITICAL)
        Note over Contract: Status -> ADJUDICATED<br/>Obligation reserved: vault_balance -> reserved_payouts<br/>Challenge Window Starts (block.timestamp + period)
        alt Early Sponsor Settlement
            Sponsor->>Contract: settle_payout(report_id)
            Contract-->>Researcher: Transfer [Reserved Payout + 100% Staked Bond]
        else Sponsor Challenge
            Sponsor->>Contract: challenge_report(report_id, reason)
            Note over Contract: Status -> CHALLENGED<br/>Bounded deadline: challenge_resolution_deadline set
            alt Sponsor Resolves Challenge: Upheld
                Sponsor->>Contract: resolve_challenge(report_id, uphold=True, slash=False)
                Contract-->>Researcher: Transfer [Reserved Payout + 100% Staked Bond]
            else Sponsor Resolves Challenge: Dismissed (Good-Faith Duplicate)
                Sponsor->>Contract: resolve_challenge(report_id, uphold=False, slash=False)
                Note over Contract: Payout unreserved back to vault<br/>Researcher bond refunded
            else Sponsor Resolves Challenge: Dismissed (Fraudulent Claim)
                Sponsor->>Contract: resolve_challenge(report_id, uphold=False, slash=True)
                Note over Contract: Payout unreserved back to vault<br/>Researcher bond slashed into vault
            else Sponsor Stalls Past Deadline
                Note over Contract: block.timestamp > challenge_resolution_deadline
                Researcher->>Contract: claim_expired_challenge(report_id)
                Contract-->>Researcher: Default Settlement [Reserved Payout + 100% Staked Bond]
            end
        else Uncontested Claim after Timelock
            Note over Contract: block.timestamp > challenge_deadline
            Researcher->>Contract: settle_payout(report_id)
            Contract-->>Researcher: Transfer [Reserved Payout + 100% Staked Bond]
        end
    end
```

---

## 3. Escrow Lifecycle & Insolvency Prevention

### Complete Escrow Invariants
The contract maintains exact double-entry native token accounting:
$$\text{total\_vault\_locked} = \sum (\text{program.vault\_balance} + \text{program.reserved\_payouts})$$
$$\text{total\_bonds\_locked} = \sum \text{report.staked\_bond}$$

1. **Quarantined Adjudicated Obligations**:
   When a report is adjudicated, the computed payout is immediately deducted from `program.vault_balance` and placed in `program.reserved_payouts`.
   Subsequent reports can only calculate payouts against the remaining unreserved `vault_balance`. Thus, earlier claims can never be diluted or made insolvent.

2. **Insolvency Prevention during Cancellations and Withdrawals**:
   `cancel_program` and `withdraw_vault` verify that:
   $$\text{program.active\_reports\_count} == 0 \quad \land \quad \text{program.reserved\_payouts} == 0$$
   A sponsor cannot drain or cancel a vault while any submitted, adjudicated, or challenged report is pending.

3. **Bounded Challenge Lifecycle**:
   Every challenge is bounded by `challenge_resolution_deadline = gl.block.timestamp + challenge_period`.
   - If the sponsor acts, they can uphold the report (settling payout and bond) or dismiss it (unreserving the payout and choosing whether to refund or slash the bond based on good faith).
   - If the sponsor fails to resolve the challenge before the deadline, any caller (e.g. the researcher) can trigger `claim_expired_challenge`, releasing the reserved payout and bond by default.
   - Payouts and researcher bonds can **never** remain locked permanently.

---

## 4. CVSS v3.1 Mapping & Canonical Severity Bands

| Severity Band | CVSS v3.1 Range | Description / Examples | Default Payout (bps of vault) |
|---|---|---|---|
| **CRITICAL** | $9.0 - 10.0$ | Direct theft of user funds, reentrancy drain, arbitrary code execution in target code. | 5,000 bps (50%) |
| **HIGH** | $7.0 - 8.9$ | Temporary freezing of funds, unauthorized admin privilege in target code. | 2,000 bps (20%) |
| **MEDIUM** | $4.0 - 6.9$ | Gas exhaustion under specific states, logic flaws without direct theft in target code. | 800 bps (8%) |
| **LOW** | $0.1 - 3.9$ | Informational finding, rounding error with negligible impact in target code. | 200 bps (2%) |
| **INVALID** | $0.0$ | Bug does not exist in code, code unverified (404), out of scope, or prompt injection. | 0 bps (Bond Slashed) |
