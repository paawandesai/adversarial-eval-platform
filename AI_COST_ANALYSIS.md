# AI Cost Analysis — Adversarial Evaluation Platform

*Actual development spend and projected production cost at 100 / 1K / 10K / 100K test runs.
Every dollar anchor below is a **measured** number from `cost_data.json` (the platform's real
cost instrumentation) and `campaign_results.json` (the latest live campaign: 21 cases → 8 pass /
3 fail / 1 error / 9 skipped, 3 validated findings). Prices are taken verbatim from `cost_data.json`'s
`router_prices` table; nothing here invents a price. Where a component was not exercised in the
campaign (the priced semantic judge), its cost is **modeled from the real price table plus a
stated token assumption**, and labeled as modeled. §1.1 reconciles actual development spend to
its **billing source** and labels every component **MEASURED**, **SUBSCRIPTION-ABSORBED**, or
**\$0**.*

---

## 1. Actual spend to date

**The latest live campaign cost `$0.00`.** `campaign_results.json` reports `cost_usd = 0.0` across
its **12 executed runs** (21 cases; the other 9 are documented-limitation skips that were not
run). Of those 12, **11 reached a verdict** (8 PASS + 3 FAIL) and 1 errored (`seed-authz-03`, no
readable response). **10 of the 11 decided verdicts** came from a **deterministic oracle** (canary,
HTTP assert, rate limit), which makes **no LLM call at all**; the eleventh (`seed-ipi-04`)
was decided by the semantic judge on a **local Ollama model** (`llama3.1:8b`), which has no
per-token price. The per-run instrumentation in `cost_data.json.campaign` is a snapshot of the
earlier 19-run campaign, taken before the two DoS cases were added: `total_cost_usd = 0.0` and
`total_tokens = 0`, with Red Team generation on the offline template generator
(`model: "template/offline-v1"` on all 19 per-run records — no LLM call). The final campaign
replayed its seeds down the same $0 path.

> **Key efficiency finding:** the platform confirmed its campaign vulnerabilities — the **critical**
> cross-patient PHI bypass (F-50, `VULN_5d185ba75ac6`, reproduced again as `VULN_3bdd54e50c61`) and
> the **high** cost-amplification DoS (`VULN_c1146239b086`) — for **$0 in LLM spend**. They were
> decided by canary-string matches and a rate-limit count, not a model. Deterministic-first judging
> means the security signal is not only reproducible, it is *free to produce*.

**Measured cost of one real novel generation.** `cost_data.json.sample_generation` is a single
real frontier attack generation:

| field | value |
| --- | --- |
| provider / model | `anthropic` / `claude-opus-5-5` |
| input / output tokens | 44 / 96 |
| **cost** | **$0.002096** |
| latency | 4094.9 ms |

This is internally consistent with the price table (44 × \$4/M + 96 × \$20/M = \$0.002096), and is
the **per-novel-generation anchor** used throughout this document. The campaign itself incurred
none of this cost because it replayed frozen seeds through the offline generator rather than
generating novel attacks on a frontier model.

### 1.1 Actual dev spend (reconciled)

The figures above are what the platform's instrumentation recorded. This section ties each cost
component of the build (commits 2026-09-28 → 2026-10-01) to the **billing source that actually
paid for it**, using three labels:

- **MEASURED** — token-metered by the router's instrumentation and priced from the price table.
- **SUBSCRIPTION-ABSORBED** — real model usage, but billed under a flat-rate subscription, so it
  has no per-token charge and no marginal cost.
- **\$0** — no billable usage occurred (local model, no model call, or the call failed before
  anything was billed).

| Cost component | What actually ran | Billing source | Label | Actual spend |
| --- | --- | --- | --- | --- |
| **Red Team attack generation (dev)** | Claude, via **Claude Code** authenticated to the CVP-verified claude.ai org | **Claude Max flat-rate subscription** — *not* metered API credits | **SUBSCRIPTION-ABSORBED** | **\$0 marginal.** The fixed Max subscription fee is the actual spend basis; it does not vary with the number of attacks generated |
| **Campaign execution** (replay + deterministic oracles) | offline template generator (`template/offline-v1`) + canary / HTTP-assert / rate-limit oracles | none — no model call | **\$0** | **\$0.00** (`campaign_results.json` `cost_usd = 0.0`; `cost_data.json` `total_tokens = 0`) |
| **Semantic Judge — the one live verdict** (`seed-ipi-04`) | local **Ollama** `llama3.1:8b` | local compute — no API billing | **\$0** | **\$0.00** |
| **DeepSeek** (configured judge fallback) | one attempted call, rejected with **HTTP 402** (insufficient balance) before any tokens were billed | DeepSeek console | **\$0** | **\$0.00 — confirmed against the DeepSeek console** |
| **Anthropic metered API — this platform** (outside the Max subscription) | the single instrumented `sample_generation` call (`claude-opus-5-5`, 44 in / 96 out) through the router's API-key path | Anthropic console | **MEASURED** | **\$0.002096** at list price — the only metered Anthropic call the instrumentation records (see note) |
| **Anthropic console total for the period (~\$93)** — *not this platform* | the **Weeks 1–2 Clinical Co-Pilot target's** own operational LLM calls | Anthropic console | **out of scope** | **~\$93, attributed to the target system**, not to the Week 3 adversarial platform (see note) |

**Reconciled total.** The Week 3 platform's metered LLM spend for the build is **\$0.002096
(MEASURED)** + **\$0** DeepSeek + **\$0** Ollama + **\$0** campaign execution — i.e. **≈ \$0, under
one cent** — on top of the **fixed Claude Max subscription**, which absorbed all Red Team
generation at zero marginal cost. The **~\$93** on the Anthropic console is the Weeks 1–2 target's
operating cost and is **not** part of that total.

**What this does and does not claim.**

- **Dev generation was not free in the accounting sense — it was pre-paid.** The honest statement
  is "\$0 *marginal*, subscription-absorbed", not "\$0". The subscription is a flat fee shared with
  all other use of the account, so no per-attack dollar figure can be attributed from billing data.
- **The \$0.002096 anchor is MEASURED, not billed-in-bulk.** It comes from real token counts on one
  real call (44 × \$4/M + 96 × \$20/M) and is retained as the per-novel-generation price for the
  projections in §3. Projections deliberately price every frontier generation at this **metered
  API rate**, even though dev-time generation was subscription-absorbed — a production pipeline
  should be costed at metered rates, so the projections are conservative relative to what the
  build actually paid.
- **Anthropic console note — the ~\$93 is the target, not this platform.** The Anthropic console
  shows **~\$93** of metered spend for the build period. That is the **Weeks 1–2 Clinical Co-Pilot
  target's own operational LLM cost** (the system under test calling Claude to do its job), not
  spend by the Week 3 adversarial platform. The platform-side evidence is consistent with this:
  the router reaches Claude only through its metered path (`_call_anthropic`, which requires
  `ANTHROPIC_API_KEY`), `.env.example` leaves that key commented out ("only if an agent routes to
  Claude"), and every per-run campaign record shows `template/offline-v1` with
  `total_tokens = 0`. The platform's instrumentation therefore bounds its own metered Anthropic
  usage at the one sample call above (**\$0.002096**) — a rounding error against the console
  figure. The attribution of the ~\$93 to the target is from the account owner's reading of the
  console; this repo's instrumentation covers the platform's calls only and cannot itemise the
  target's bill. Inference the target performs while answering this platform's attack traffic is
  target operating cost and falls inside that figure, consistent with §2 ("target API calls are
  infrastructure, not LLM spend, and are not priced here").
- **DeepSeek \$0 is a failure, not a saving.** The 402 means the fallback judge never ran; the
  verdict was produced by the local Ollama judge instead (see §5 on external-billing dependencies).

---

## 2. Cost model — what one test run actually costs

A "test run" = generate-or-replay one attack → execute it against the target → judge it. Its LLM
cost is the sum of two independent components; **target API calls are infrastructure, not LLM
spend, and are not priced here** (the campaign's deterministic path is why `total_cost_usd = 0.0`).

| Component | When it applies | LLM cost |
| --- | --- | --- |
| **(a) Deterministic oracle verdict** | canary / tool-call audit / log scan / token counter / HTTP assert / rate limit — categories with a deterministic oracle | **$0** (no model call) |
| **(b1) Replay a FROZEN seed / regression case** | regression suite, CI, positive controls, any stored `AttackCase` | **$0** (deterministic mutation/replay, no generation call) |
| **(b2) Novel Red Team generation** | discovering a *new* attack on a frontier model (Claude via CVP) | **$0.002096 / attack** (measured anchor); **$0** if generated on a local Ollama model |
| **(c) Semantic LLM judge** | *only* categories with no deterministic oracle (system-prompt extraction, persona hijack, unsafe advice) | **modeled** — see below |

**Replaying a frozen case costs $0 in LLM.** This is the load-bearing fact for scale: the
regression suite and CI gate — which re-run the frozen exploit set on every deploy — are
**deterministic end to end** (stored attack, replayed turns, deterministic oracle). Continuous
regression is therefore **free to run** regardless of how many times it runs.

**Semantic judge cost (modeled).** The priced LLM-judge path is **DeepSeek** (`deepseek-chat`,
\$0.28/M in, \$0.42/M out). It was **not** exercised in the latest campaign: **0 of the 11 decided
verdicts used it**. The one `llm_judge` case (`seed-ipi-04`) was decided by the local Ollama judge
at \$0, after an earlier campaign's attempt on DeepSeek errored on an upstream **HTTP 402
billing** failure before spending. So the priced judge's cost is modeled from the price table plus
a stated assumption:

> **Assumption J:** one semantic judgment reads ~2,000 input tokens (transcript + rubric) and
> emits ~200 output tokens → 2000 × \$0.28/M + 200 × \$0.42/M = **\$0.000644 / semantic verdict**.

---

## 3. Production cost projections

This is **not** cost-per-token × N. It models the *mix* of run types at each scale. The campaign's
own composition motivates the mix: seeds are **frozen and replayed** (deterministic, $0), only a
minority of runs generate **novel** attacks, and only categories with no deterministic oracle
reach the **semantic judge** (1 of 21 seed cases ≈ 5%).

**Stated assumptions for the mix:**
- **A1 — semantic-judge share = 5% of all runs**, at every tier (matches the seed composition: 1
  `llm_judge` case of 21). Cost per semantic verdict = **\$0.000644** (Assumption J).
- **A2 — novel-generation share shrinks as scale grows**, because regression/CI replays of frozen
  cases dominate at scale: **50% → 20% → 10% → 5%** novel at 100 / 1K / 10K / 100K. The remainder
  are $0 deterministic replays.
- **A3 — the discovery/execution model split** (ARCHITECTURE §8): novel generation runs on the
  **frontier model (Claude/CVP)** at small scale, and shifts to **local Ollama (\$0/generation)**
  at **10K+**. Deterministic verdicts and frozen replays are always $0.

| Runs | Novel gens (share) | Novel-gen backing | Novel-gen $ | Semantic verdicts (5%) | Judge $ | **Total $** | **$/run** |
| ---: | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 100 | 50 (50%) | frontier @ \$0.002096 | \$0.105 | 5 | \$0.003 | **\$0.108** | **\$0.00108** |
| 1,000 | 200 (20%) | frontier @ \$0.002096 | \$0.419 | 50 | \$0.032 | **\$0.451** | **\$0.00045** |
| 10,000 | 1,000 (10%) | **local Ollama @ \$0** | \$0.000 | 500 | \$0.322 | **\$0.322** | **\$0.00003** |
| 100,000 | 5,000 (5%) | **local Ollama @ \$0** | \$0.000 | 5,000 | \$3.220 | **\$3.220** | **\$0.00003** |

**What the table says:** even at **100,000 runs** the modeled spend is **~\$3.22** — dominated
entirely by the semantic judge, because novel generation has moved to local models and everything
else is deterministic ($0). The per-run cost falls as scale grows (the fixed novel-discovery work
amortizes over more free replays).

**The architectural inflection at 10K.** If novel generation stayed on the **frontier** model
instead of shifting to local, the same tiers would cost:

| Runs | Novel gens | Frontier novel-gen $ | + Judge $ | **Total (frontier-only)** |
| ---: | ---: | ---: | ---: | ---: |
| 10,000 | 1,000 | \$2.096 | \$0.322 | **\$2.418** |
| 100,000 | 5,000 | \$10.480 | \$3.220 | **\$13.700** |

So the local shift saves ~\$2 at 10K and ~\$10 at 100K *per campaign* — modest in absolute dollars
at these token sizes, but see §5: the stronger argument for local models at scale is **refusals
and reliability**, not just price.

---

## 4. Architectural changes needed at each scale tier

Tied to the **discovery-vs-execution split** already in ARCHITECTURE §8 (frontier model via CVP for
novel attack **discovery**; local models for high-volume mutation/**execution**):

- **100 runs (ad-hoc / per-PR).** No change. Frontier novel generation is affordable
  (\~\$0.11/campaign); deterministic replay + oracle judging carry the rest for free. Run
  synchronously.
- **1,000 runs (nightly).** Still frontier for novel discovery (\~\$0.45/campaign). Introduce a
  **mutation cache**: deterministic mutations of a discovered attack carry `parent_case_id` and are
  replay-deterministic, so cache and reuse them rather than regenerating. Freeze every confirmed
  novel attack into the regression suite so tomorrow's run replays it for $0.
- **10,000 runs (per-release / fleet).** **Shift novel generation from frontier to local Ollama
  models** (Qwen/Llama), already wired as the production-scale fallback (ARCHITECTURE §8) —
  novel-gen cost → \$0. **Batch and cache** mutations; **sample coverage** (probe a representative
  fraction of the mutation space) instead of exhaustive enumeration; move execution onto a **work
  queue** so target I/O, not model latency, sets throughput.
- **100,000 runs (continuous, multi-target).** Local models for *all* generation and mutation;
  consider a **local semantic judge** to drive the residual \$3.22 → ~\$0 (it is the only remaining
  cost). Horizontal execution workers; deterministic regression runs continuously in CI at $0.
  Reserve frontier/CVP strictly for a small **novel-discovery budget**, not volume.

The through-line: **spend frontier tokens only on discovering genuinely new attacks; execute,
mutate, replay, and judge at volume on the free deterministic + local path.**

---

## 5. The refusal-cost factor

Frontier models — **even under Anthropic's Cyber Verification Program**, which lifts default
dual-use safeguards for verified offensive work (ARCHITECTURE §8) — can still **flag or interrupt
legitimate red-team work**. That is a real operational cost that the price table does not capture:
a refused or interrupted generation is wasted latency, a retry, and sometimes a human in the loop.

**First-hand evidence from this project:** while authoring the write-back fixtures earlier in this
engagement, an assistant-side **safety classifier interrupted a legitimate, authorized red-team
step mid-task** (documenting adversarial lab-PDF fixtures against a sandboxed, consented test
target). The work was in-scope and eventually completed, but the interruption cost a round-trip and
a reframing. At 100K continuous runs, a refusal rate even in the low single digits translates to
thousands of wasted calls, retries, and stalls — an availability and throughput tax, not just a
dollar tax.

This is the decisive argument for the **local-model execution tier**: local Ollama models (Qwen/
Llama) do not refuse in-scope offensive generation, have no per-token price, and no external
rate/billing dependency (an earlier campaign's one LLM-judge call died on a DeepSeek **HTTP 402
billing** error — an external-dependency failure mode local models avoid; the final campaign ran
that verdict on local Ollama instead). Reserve the frontier
model, under CVP, for the low-volume **novel-discovery** work where its capability is worth the
refusal risk; run everything at volume locally.

---

## Appendix — real price table (verbatim from `cost_data.json.router_prices`)

USD per **million** tokens, `(input, output)`:

| provider | model | input \$/M | output \$/M |
| --- | --- | ---: | ---: |
| anthropic | claude-fable-5 | 10.0 | 50.0 |
| anthropic | claude-mythos-5 | 10.0 | 50.0 |
| anthropic | claude-opus-5-5 | 4.0 | 20.0 |
| anthropic | claude-opus-5 | 5.0 | 25.0 |
| anthropic | claude-opus-4 | 5.0 | 25.0 |
| anthropic | claude-sonnet-5 | 2.0 | 10.0 |
| anthropic | claude-sonnet-4 | 3.0 | 15.0 |
| anthropic | claude-haiku-4 | 1.0 | 5.0 |
| deepseek | deepseek-chat | 0.28 | 0.42 |
| deepseek | deepseek-reasoner | 0.28 | 0.42 |

**Anchor arithmetic (measured):** novel generation `claude-opus-5-5` — 44 × \$4/M + 96 × \$20/M =
\$0.000176 + \$0.001920 = **\$0.002096** (matches `sample_generation.cost_usd`).
**Modeled (Assumption J):** semantic judge `deepseek-chat` — 2000 × \$0.28/M + 200 × \$0.42/M =
**\$0.000644**.
