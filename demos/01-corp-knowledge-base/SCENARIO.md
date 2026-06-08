# Scenario: Corporate KB with poisoned duplicate

An attacker uploaded a near-duplicate of the HR policy with backdoor triggers.

## Expected findings

- RS-DUP-001 × 2
- RS-TRIG-001 (backdoor trigger in fake HR policy)
- RS-OUT-001 × 2

## Why this matters

Real attack pattern: poison the KB so questions about HR policy retrieve the malicious version first.
