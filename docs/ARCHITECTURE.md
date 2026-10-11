# Architecture & Technical Specification: AgenticBugBounty

## 1. Executive Summary

`AgenticBugBounty` is a decentralized, autonomous bug bounty triage and payout protocol built natively on GenLayer. It replaces slow, costly, and centralized bug bounty intermediaries (such as Immunefi or HackerOne triage desks) with deterministic on-chain consensus executed by GenLayer Intelligent Validators.

Key Innovations:
- **Autonomous Scope Verification**: Non-deterministic web fetch (`gl.nondet.web.get`) cross-references target files against live GitHub `security.md` scopes.
- **On-Chain CVSS v3.1 Triage**: Validators evaluate vulnerability reproduction, attack vector, privileges required, and impact to compute standardized CVSS scores.
- **Equivalence Principle with Canonical Severity Bands**: Leader nodes propose evaluations, but validators strictly enforce matching canonical severity bands (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INVALID`) and bounded CVSS score tolerances ($\pm 0.8$).
- **Deterministic Escrow Payouts**: Payouts are computed mathematically from pre-configured basis points of the active vault—eliminating leader hallucination or discretionary bias.
- **Anti-Spam Game Theory & Slashing**: Researchers stake a refundable bond (`min_stake`). Valid bugs refund 100% of the bond with the reward; fraudulent or spam reports are slashed directly into the project vault.
- **Enforced On-Chain Timelocks**: Researchers cannot claim payouts before the challenge deadline elapses (`gl.block.timestamp > challenge_deadline`), preserving sponsor review rights while guaranteeing trustless release if undisputed.

---

## 2. End-to-End Workflow & State Machine

```mermaid
sequenceDiagram
    autonumber
    actor Sponsor as Protocol Sponsor
    actor Researcher as Security Researcher
    participant Contract as AgenticBugBounty (GenLayer)
    participant Validators as GenLayer Validator Consensus
    participant Web as Public Web (GitHub / Security.md)

    Sponsor->>Contract: create_program(name, scope_url, min_stake, payouts) + [Vault Native Value]
    Note over Contract: Vault locked in escrow

    Researcher->>Contract: submit_report(target, title, PoC) + [Anti-Spam Stake]
    Note over Contract: Anti-spam bond locked; excess refunded immediately

    Contract->>Validators: triage_report(report_id)
    Validators->>Web: gl.nondet.web.get(scope_url)
    Validators->>Validators: gl.nondet.exec_prompt(CVSS v3.1 Rubric)
    Validators->>Validators: Equivalence check (Canonical Severity Band)
    Validators-->>Contract: Consensus Finalized (Severity, CVSS, Summary)

    alt Report Invalid / Out-of-Scope / Spam
        Note over Contract: Status -> REJECTED<br/>Anti-spam bond slashed into Vault
    else Report Valid (LOW, MEDIUM, HIGH, CRITICAL)
        Note over Contract: Status -> ADJUDICATED<br/>Challenge Window Starts (block.timestamp + period)
        alt Early Sponsor Settlement
            Sponsor->>Contract: settle_payout(report_id)
            Contract-->>Researcher: Transfer [Bounty + 100% Staked Bond]
        else Dispute / Challenge by Sponsor
            Sponsor->>Contract: challenge_report(report_id, reason)
            Note over Contract: Status -> CHALLENGED
        else Uncontested Claim after Timelock
            Note over Contract: block.timestamp > challenge_deadline
            Researcher->>Contract: settle_payout(report_id)
            Contract-->>Researcher: Transfer [Bounty + 100% Staked Bond]
        end
    end
```

---

## 3. Consensus Architecture & Equivalence Principle

GenLayer's Non-Deterministic Consensus guarantees that subjective and web-dependent data yields deterministic execution state across validators.

### Leader-Validator Execution Model

1. **Leader Execution (`_leader_evaluate`)**:
   - Queries `scope_url` via `gl.nondet.web.get()`.
   - Formulates a system-prompted LLM request containing the scope text, component path, and untrusted researcher PoC.
   - Executes `gl.nondet.exec_prompt(prompt, response_format="json")`.
   - Parses response and derives canonical severity band from CVSS score.
   - Returns structured proposal:
     ```json
     {
       "in_scope": true,
       "is_valid": true,
       "severity": "CRITICAL",
       "cvss_x10": 98,
       "summary": "Classic reentrancy in withdraw() allows complete draining."
     }
     ```

2. **Validator Execution & Equivalence Check (`_validator_evaluate`)**:
   - Validator independently fetches `scope_url` and independently executes `gl.nondet.exec_prompt()`.
   - **Equivalence Rule Set**:
     $$\text{Equivalence} = \begin{cases}
     \text{True} & \text{if } \text{in\_scope}_V == \text{in\_scope}_L \land \text{is\_valid}_V == \text{is\_valid}_L \\
                 & \land \; \text{severity}_V == \text{severity}_L \\
                 & \land \; |\text{cvss\_x10}_V - \text{cvss\_x10}_L| \le 8 \\
     \text{False} & \text{otherwise}
     \end{cases}$$
   - If validator disagrees on canonical severity (e.g. Leader says `HIGH` but Validator says `LOW`), consensus rejects the leader proposal immediately.

---

## 4. CVSS v3.1 Mapping & Canonical Severity Bands

| Severity Band | CVSS v3.1 Range | Description / Examples | Default Payout (bps of vault) |
|---|---|---|---|
| **CRITICAL** | $9.0 - 10.0$ | Direct theft of user funds, reentrancy drain, arbitrary code execution, permanent lockup. | 5,000 bps (50%) |
| **HIGH** | $7.0 - 8.9$ | Temporary freezing of funds, unauthorized admin state change, high-impact DOS. | 2,000 bps (20%) |
| **MEDIUM** | $4.0 - 6.9$ | Gas exhaustion under specific states, logic flaws without direct theft, fee accounting leakage. | 800 bps (8%) |
| **LOW** | $0.1 - 3.9$ | Informational finding, rounding error with negligible impact, non-critical frontrunning. | 200 bps (2%) |
| **INVALID** | $0.0$ | Out of scope, non-reproducible, false positive, frivolous claim, or prompt injection attempt. | 0 bps (Bond Slashed) |

---

## 5. Security Model & Adversarial Defenses

1. **Prompt Injection Mitigation**:
   - Pre-validation regex filter (`PROMPT_INJECTION_PATTERNS`) rejects known jailbreak phrases at submission time.
   - LLM prompt wraps user PoC in `<untrusted_researcher_poc>` tags with explicit defensive system directives.
2. **Deterministic Mathematical Settlements**:
   - Payout calculations are derived strictly from contract state: $\text{payout} = (\text{vault\_balance} \times \text{bps}) / 10000$.
3. **Exact Native Escrow & Zero Capital Trap**:
   - All excess native value sent beyond required deposits/stakes is calculated and refunded back to `gl.message.sender_address` via `emit_transfer`.
4. **On-Chain Timelock Defense**:
   - Researchers are strictly prohibited from calling `settle_payout` before `gl.block.timestamp > challenge_deadline`.
