# Architecture & Technical Specification: AgenticBugBounty

## 1. Executive Summary

`AgenticBugBounty` is a decentralized, autonomous bug bounty triage and payout protocol built natively on GenLayer. It replaces slow, costly, and centralized bug bounty intermediaries (such as Immunefi or HackerOne triage desks) with deterministic on-chain consensus executed by GenLayer Intelligent Validators.

Key Innovations:
- **Authoritative Target Code Acquisition**: Validators deterministically derive and fetch the referenced target source code at the specified commit/version (`code_url = {repo_base_url}/{commit}/{target_component}`) via `gl.nondet.web.get` before evaluating the vulnerability.
- **Autonomous Scope Verification**: Non-deterministic web fetch (`gl.nondet.web.get`) cross-references target files against live project `security.md` scopes.
- **Pure Functional Nondeterministic Flow (GenVM Compliant)**: Nondeterministic triage callbacks (`leader_fn` and `validator_fn`) are strictly pure closures capturing only local primitive arguments. No contract storage (`self`) or storage writes are reachable from the nondeterministic context.
- **On-Chain CVSS v3.1 Triage**: Validators inspect the real source code and researcher PoC to evaluate vulnerability existence, attack vector, privileges required, and impact to compute standardized CVSS scores.
- **Equivalence Principle with Canonical Severity Bands**: Leader nodes propose evaluations, but validators strictly enforce matching canonical severity bands (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INVALID`) and bounded CVSS score tolerances ($\pm 0.8$).
- **Deterministic Escrow Payouts**: Payouts are computed mathematically from pre-configured basis points of the active vault—eliminating leader hallucination or discretionary bias.
- **Anti-Spam Game Theory & Slashing**: Researchers stake a refundable bond (`min_stake`). Valid bugs refund 100% of the bond with the reward; unverified code, fraudulent, or spam reports are slashed directly into the project vault.
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
    participant GitWeb as Authoritative Repository (GitHub / Code Host)

    Sponsor->>Contract: create_program(name, repo_base_url, scope_url, min_stake, payouts) + [Vault Native Value]
    Note over Contract: Vault locked in escrow

    Researcher->>Contract: submit_report(target_component, commit_version, title, PoC) + [Anti-Spam Stake]
    Note over Contract: Anti-spam bond locked; excess refunded immediately

    Contract->>Validators: triage_report(report_id)
    Note over Validators: Pure functional closure executes with local primitives (No storage reachable)
    Validators->>GitWeb: 1. gl.nondet.web.get(scope_url) -> Verify scope
    Validators->>GitWeb: 2. gl.nondet.web.get(code_url) -> Authoritative code at commit
    Validators->>Validators: 3. gl.nondet.exec_prompt(Target Code + PoC + CVSS Rubric)
    Validators->>Validators: 4. Equivalence check (Canonical Severity Band & Code Verification)
    Validators-->>Contract: Consensus Finalized (Severity, CVSS, CodeVerified, Summary)

    alt Report Invalid / Out-of-Scope / Code Unverified / Spam
        Note over Contract: Deterministic State Write: Status -> REJECTED<br/>Anti-spam bond slashed into Vault
    else Report Valid (LOW, MEDIUM, HIGH, CRITICAL)
        Note over Contract: Deterministic State Write: Status -> ADJUDICATED<br/>Challenge Window Starts (block.timestamp + period)
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

### GenVM Lint Compliant Execution Model

1. **Pure Closure Design**:
   All state variables (`repo_base_url`, `scope_url`, `target_component`, `commit_or_version`, `title`, `details`, `claimed_severity`) are extracted into local strings inside `triage_report()` prior to invoking `gl.vm.run_nondet_unsafe`.
   The `leader_fn` and `validator_fn` closures reference only these primitives and call pure top-level helper functions. No `self` reference exists within the callbacks, preventing any storage writes or reads from the nondeterministic triage context.

2. **Authoritative Code Acquisition**:
   - `code_url = f"{repo_base_url.rstrip('/')}/{commit_or_version.strip()}/{target_component.strip().lstrip('/')}"`
   - If the code cannot be fetched (HTTP != 200), `code_verified` is marked `False`, causing the report to be rejected as `INVALID`.
   - The LLM receives the real source code at that specific commit and verifies whether the vulnerability genuinely exists.

3. **Validator Equivalence Check (`perform_validator_triage`)**:
   - Validator independently fetches the authoritative scope and target source code.
   - **Equivalence Rule Set**:
     $$\text{Equivalence} = \begin{cases}
     \text{True} & \text{if } \text{in\_scope}_V == \text{in\_scope}_L \\
                 & \land \; \text{code\_verified}_V == \text{code\_verified}_L \\
                 & \land \; \text{is\_valid}_V == \text{is\_valid}_L \\
                 & \land \; \text{severity}_V == \text{severity}_L \\
                 & \land \; |\text{cvss\_x10}_V - \text{cvss\_x10}_L| \le 8 \\
     \text{False} & \text{otherwise}
     \end{cases}$$
   - If validator disagrees on canonical severity or code verification, consensus rejects the leader proposal immediately.

---

## 4. CVSS v3.1 Mapping & Canonical Severity Bands

| Severity Band | CVSS v3.1 Range | Description / Examples | Default Payout (bps of vault) |
|---|---|---|---|
| **CRITICAL** | $9.0 - 10.0$ | Direct theft of user funds, reentrancy drain, arbitrary code execution in target code. | 5,000 bps (50%) |
| **HIGH** | $7.0 - 8.9$ | Temporary freezing of funds, unauthorized admin privilege in target code. | 2,000 bps (20%) |
| **MEDIUM** | $4.0 - 6.9$ | Gas exhaustion under specific states, logic flaws without direct theft in target code. | 800 bps (8%) |
| **LOW** | $0.1 - 3.9$ | Informational finding, rounding error with negligible impact in target code. | 200 bps (2%) |
| **INVALID** | $0.0$ | Bug does not exist in target code, code unverified, out of scope, or prompt injection. | 0 bps (Bond Slashed) |

---

## 5. Security Model & Adversarial Defenses

1. **Authoritative Code Verification**:
   - Narratives without matching vulnerable logic in the acquired target code are automatically marked `INVALID`.
2. **Prompt Injection Mitigation**:
   - Pre-validation regex filter (`PROMPT_INJECTION_PATTERNS`) rejects known jailbreak phrases at submission time.
   - LLM prompt wraps user PoC in `<untrusted_researcher_poc>` tags with explicit defensive system directives.
3. **Deterministic Mathematical Settlements**:
   - Payout calculations are derived strictly from contract state: $\text{payout} = (\text{vault\_balance} \times \text{bps}) / 10000$.
4. **Exact Native Escrow & Zero Capital Trap**:
   - All excess native value sent beyond required deposits/stakes is calculated and refunded back to `gl.message.sender_address` via `emit_transfer`.
5. **On-Chain Timelock Defense**:
   - Researchers are strictly prohibited from calling `settle_payout` before `gl.block.timestamp > challenge_deadline`.
