# USERS.md — Who the Adversarial Evaluation Platform Is For

*This document defines the platform's user — not the clinician who uses the Clinical Co-Pilot (that is the target's user), but the person responsible for assuring the Co-Pilot is safe to deploy. Every platform capability traces back to a use case here.*

---

## The user

**A security / AI-red-team engineer responsible for the Clinical Co-Pilot's security posture** — on a small AppSec or AI-safety team (2–4 people) at the health system or the vendor that ships the Co-Pilot. Concretely: the engineer who has to **sign off that each new build of the Co-Pilot has not opened a way to leak PHI, cross patient boundaries, or misuse a tool — on a release cadence measured in days, not quarters.**

This is a deliberately narrow user, and the narrowness matters. It is *not* "security teams need help testing AI." It is one person, with one recurring, high-stakes decision — *ship this build or block it* — under two constraints that break the usual approach:

1. **Cadence.** The Co-Pilot's model, system prompt, retrieval config, and tool set change frequently (a new model version, a reworded prompt, a new FHIR scope). A manual penetration test per release does not scale to a weekly-or-faster cadence.
2. **Proof.** "I tested it and it seemed fine" is not a sign-off a hospital will accept for a system that touches PHI. The engineer needs *reproducible evidence* that a specific class of attack fails, and that a fix for a past finding still holds.

The prior state of the world — manual prompting, a static list of known attack payloads, a fix validated once and never re-checked — fails both constraints. Static payload lists go stale as attacks mutate; one-time validation can't catch a regression three deploys later; and manual testing can neither run continuously nor produce consistent, reproducible reports.

---

## The workflow the platform enters

Walk through the engineer's day at the moment the platform matters. A new Co-Pilot build is staged for deployment. In the thirty minutes before they either approve it or block it, they need to answer: *did this change introduce a cross-patient path, a prompt-injection bypass, a write-back abuse, or a PHI-in-logs leak — and did it reopen anything we previously fixed?* They cannot hand-test the full attack surface in that window, and they cannot prove a negative by clicking around. They need a system that has already probed the build, judged the results with evidence, filed reproducible reports, and re-run every past exploit — and that hands them a coverage view and a block/allow signal.

---

## Use cases

Each use case states, explicitly, why an **autonomous multi-agent system** is the right shape — not a dashboard, not a static test runner, not a single clever agent.

### UC-1 — Pre-deployment security gate
The engineer runs the full adversarial suite against a candidate build; a critical finding or a regression blocks the deploy.
**Why automation, and why multi-agent:** the attack surface *mutates* between builds, so a fixed checklist goes stale — you need an agent that *generates and mutates* attacks (Red Team), not a static list. And the attacker cannot be trusted to grade its own success — a system that both generates an attack and judges it has a conflict of interest by construction — so judgment must be a *separate* agent with independent, deterministic evidence (Judge). A dashboard or a sorted list can't do either; it can only display what a human already found.
**Serves:** Red Team, Judge, deterministic oracles, the deploy-gating verdict.

### UC-2 — Continuous / post-deployment probing
Overnight and between releases, the platform probes the live system, surfaces coverage gaps, and escalates partially-successful attacks into variants.
**Why automation, and why multi-agent:** no engineer runs adversarial campaigns at 2 a.m. continuously, and deciding *what to test next* (coverage gaps, unresolved findings, cost) is a different job from *executing* the tests. That separation is the Orchestrator (strategic prioritization) versus the Red Team (execution). A single agent conflating both cannot be reasoned about; a human doing the prioritization cannot keep up with the cadence.
**Serves:** Orchestrator, Red Team's mutation engine, the coverage metric.

### UC-3 — Regression assurance after a fix
When engineering ships a fix for a finding, the engineer needs proof the fix actually holds *and* did not break another category.
**Why automation, and why multi-agent:** re-running the full exploit history against every new version is exactly the repetitive, deterministic work a human should not do by hand — and the subtle failure (a test that passes because behavior changed, not because the bug was fixed) requires paired positive controls, which only a disciplined harness enforces consistently. The regression harness, anchored on the target's version, is the mechanism; a manual re-test is neither complete nor trustworthy.
**Serves:** the regression harness, positive controls, version anchoring, the CI gate.

### UC-4 — Reproducible finding documentation
A confirmed exploit must become a report a *different* engineer — who was not present when it was found — can reproduce, validate, and fix.
**Why automation, and why multi-agent:** documentation is a distinct responsibility with a distinct trust level (it recommends remediation and can trigger workflows), so it is a separate agent with a data-quality gate and a human-approval gate for critical findings. A human writing reports produces them slowly and inconsistently; an agent produces them uniformly, with the minimal reproduction and the evidence attached — but the human still approves the high-severity ones before they are published. That trust boundary is deliberate, not incidental.
**Serves:** the Documentation agent, the human-approval gate.

---

## Why *this* user constrains the whole design

Choosing the security engineer as the user — not the physician — is what makes every downstream decision defensible. Because the user needs *proof*, verdicts are deterministic-first. Because the user works on a fast cadence, testing is autonomous and continuous. Because the user must trust findings enough to block a deploy, the attacker and the judge are separate agents with separate trust levels. Because the user hands findings to a colleague, documentation is reproducible and gated. The bar is not that adversarial testing is technically possible; it is that this engineer would actually stake a PHI-touching deployment on what the platform tells them. That standard is the one the platform is built to.
