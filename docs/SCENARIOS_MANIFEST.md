# Attack Scenarios Manifest

Cryptographic provenance and schema documentation for the published
attack-scenarios dataset. Complements [`SAFETY.md`](../SAFETY.md)
responsible-use scope with a verifiable fingerprint of the released
artifact.

## File integrity

| Field | Value |
|---|---|
| Local path | `data/hf_export/attack_scenarios.jsonl` (gitignored locally; HF dataset is the canonical public copy) |
| Public mirror | https://huggingface.co/datasets/jang1563/agentshield-attack-scenarios |
| Records | **100** |
| SHA-256 | `f070654e3d0050aef123c673665f1c2ffde027692064e6c8e74679426b8a1218` |
| Snapshot date | 2026-05-14 |

To verify after downloading from the HF mirror:

```bash
huggingface-cli download jang1563/agentshield-attack-scenarios \
  attack_scenarios.jsonl --repo-type dataset --local-dir .

sha256sum attack_scenarios.jsonl
# expect: f070654e3d0050aef123c673665f1c2ffde027692064e6c8e74679426b8a1218
```

## Category distribution

The 100 scenarios are uniformly distributed across the four STRIDE-derived
attack-surface categories:

| Category | N | Coverage |
|---|---:|---|
| `direct_injection` | 25 | Prompt injection from primary user input |
| `indirect_injection` | 25 | Injection via tool outputs, retrieved documents, agent memory |
| `multi_turn_escalation` | 25 | Multi-turn conversational attacks (gradual capability escalation) |
| `tool_misuse` | 25 | Authorized tool used in unauthorized way (boundary violations) |

## Schema

Each line in the JSONL is one scenario record with the following fields:

| Field | Type | Description |
|---|---|---|
| `scenario_id` | string | Unique identifier (e.g. `DIR-001`, `IND-007`, `MTE-014`, `TM-022`) |
| `name` | string | Short human-readable scenario name |
| `category` | string | One of the four categories above |
| `description` | string | One-paragraph description of the scenario, the attacker's goal, and the agent surface tested |
| `target_surface` | string | Which agent component or interaction surface the scenario probes |
| `messages` | list[object] | Ordered conversational turns (`role`, `content`); for multi-turn scenarios, this is the full intended exchange |
| `n_turns` | integer | Number of turns in `messages` |
| `expected_behavior` | string | What a properly-defended agent should do (refuse, route, sanitize, etc.) |
| `success_criteria` | string | What constitutes a successful attack (the SuccessJudge target) |
| `nsabb_category` | string or null | Optional NSABB DURC category if the scenario touches dual-use biology; most scenarios are not bio-specific |
| `metadata` | object | Origin notes, references, related scenarios |

## Why this dataset is published openly (not gated)

The 5/7 portfolio audit recommended moving the scenario JSON to a gated
path with a SHA-256 manifest. After review, this repository deliberately
publishes the scenarios in the open while keeping the manifest. The
reasoning is documented at length in [`SAFETY.md` § "Why we publish openly"](../SAFETY.md);
the short version:

1. **The scenarios are not operational uplift.** They are abstract
   attack-category exemplars (prompt injection, multi-turn escalation,
   tool misuse, indirect injection) at the level already covered by
   OWASP LLM Top 10, the LLM red-team literature (PAIR, GCG, Lakera
   Gandalf, etc.), and any major model card's red-team section. Gating
   them would not move the attacker's frontier.
2. **Defenders need them.** The 4-component detection pipeline this
   repository ships is reproducible only if the scoring corpus is also
   reproducible. The 234+ HF dataset downloads as of 2026-05-14 are
   primarily safeguard teams testing their own agent stacks against the
   same suite. Gating would harm that audience without harming attackers.
3. **Internal consistency.** The author's broader portfolio thesis is
   *calibrated permissioning*: jointly minimize false negatives and
   false positives. Gating a non-uplift scenario corpus on precautionary
   grounds would be the same over-restriction the
   [bio-overrefusal-v0.1](https://github.com/jang1563/bio-overrefusal-v0.1)
   dataset measures in frontier LLMs. We can't ask others to calibrate
   carefully and then default-restrict our own work.

The SHA-256 manifest above gives readers the *provenance* benefit of
gating (verifiable identity of the released artifact, ability to detect
silent edits or adversarial forks) without the *availability* cost.

## Provenance

- **Authorship**: Single author (JangKeun Kim, Weill Cornell Medicine)
- **Generation method**: Hand-authored, with category-balanced sampling
  to ensure 25 records per category
- **Review**: Internal self-audit only; expert circulation pending for
  v0.2 release
- **Test target**: Released scenarios were tested against `claude-haiku-4-5-20251001`
  as the agent under test, with the BioGuard DeBERTa classifier as
  the SuccessJudge. Results in `results/results.md`.
- **Update policy**: Any future changes to the scenarios will be released
  as a new snapshot with a new SHA-256 in this manifest, not silent edits.
  Manifest history is retained in git.

## Citation

If you reproduce or extend the scenario suite, please cite the parent
repository (see [`CITATION.cff`](../CITATION.cff)) and the SHA-256
of the specific snapshot you used. Aggregate metric reproductions on
the same SHA-256 should match within ±2% (provider-side temperature
and refusal updates account for the rest).
