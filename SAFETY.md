# Responsible Use and Safety Scope

AgentShield is a **defensive security research framework** for agentic AI
systems. It exists to help builders measure and reduce the attack surface
of agent stacks, not to enable adversarial use.

## In Scope

- Security evaluation of agent stacks: STRIDE threat modeling, attack-surface
  measurement, detection-pipeline benchmarking
- Reproducing the published 100-scenario evaluation against your own agent
  stack and reporting your own ASR / FPR / detection-rate
- Extending the threat model and attack categories to new agent paradigms
  (e.g. multi-modal agents, scientific tools, embodied agents)
- Building defense components on top of the published 4-component pipeline
  and contributing improvements back

## Out of Scope

- Use of the published attack scenarios as a recipe to attack any deployed
  system you are not authorized to test
- Adversarial use of the detection-bypass analysis to engineer evasion
  payloads against any production system
- Reframing the published 100% ASR-reduction as a global claim about agent
  security (it is a slice-level result on this specific scenario suite,
  this specific BioTeam-AI agent stack, this specific Claude Haiku target;
  numbers do not transfer)
- Use without sandboxing: every reproduction should run inside Docker
  isolation per the BioTeam-AI integration documentation

## Why we publish openly (and what is provenance-protected instead)

A May 2026 portfolio audit recommended moving the scenario JSON to a gated
path. After review, this repository **deliberately keeps the scenarios
open** while adding cryptographic provenance via
[`docs/SCENARIOS_MANIFEST.md`](docs/SCENARIOS_MANIFEST.md).

The reasoning:

1. **The scenarios are not operational uplift.** They are abstract
   attack-category exemplars (prompt injection, multi-turn escalation,
   tool misuse, indirect injection) at the level already covered by
   OWASP LLM Top 10, the public LLM red-team literature (PAIR, GCG,
   Gandalf, etc.), and any major model card's red-team section. Gating
   would not move the attacker's frontier; it would only inconvenience
   defenders.
2. **Defenders need them.** The 4-component detection pipeline this
   repository ships is reproducible only if the scoring corpus is also
   reproducible. The 234+ HF dataset downloads as of 2026-05-14 are
   primarily safeguard teams running the same suite against their own
   agent stacks. Gating would harm that audience.
3. **Internal portfolio consistency.** The author's
   [bio-overrefusal-v0.1](https://github.com/jang1563/bio-overrefusal-v0.1)
   work measures *false positive* refusal cost on legitimate research.
   Default-gating a non-uplift scenario corpus on precautionary grounds
   would be the same over-restriction we ask others to calibrate down.
4. **Provenance > availability** as the actual safety risk: the more
   meaningful concern is whether someone could silently fork, modify, and
   redistribute the scenarios as if they were the canonical suite. The
   SHA-256 manifest in
   [`docs/SCENARIOS_MANIFEST.md`](docs/SCENARIOS_MANIFEST.md)
   addresses this without restricting availability.

If a specific scenario warrants gating after first release (e.g. a future
vN scenario that is more sensitive than the current category-abstract set),
that scenario will be excluded from the public dump and noted in the
manifest, rather than the entire suite being moved behind a gate.

## Withheld Content

- Per-scenario LLM responses from the evaluation runs are tracked under
  `data/responses/` only at the level needed to reproduce the metric;
  response text is filtered for any inadvertent operational detail prior
  to release.
- Internal strategy documents (positioning, role-fit analyses) are
  gitignored and never appear in the public repository.
- See [`docs/SCENARIOS_MANIFEST.md`](docs/SCENARIOS_MANIFEST.md)
  for cryptographic provenance of the scenario JSONL.

## Reporting Concerns

- A scenario you believe provides operational uplift beyond defensive value:
  open a GitHub issue with the `safety` label and the scenario ID
- A detection-pipeline gap you have evidence of: open a GitHub issue with
  the `vulnerability` label
- For sensitive disclosures: email jak4013@med.cornell.edu with subject
  "AGENTSHIELD SAFETY". Do not paste exploit detail into public issues.

## Limitations Recap

- Single target agent stack (BioTeam-AI on Claude Haiku); cross-stack
  generalization is uncharacterized
- 100-scenario suite is a calibration corpus, not exhaustive of real
  agent attack surface
- 1.0% FPR baseline measured on 100 benign scenarios; production traffic
  is much more diverse
- Detection-pipeline performance reflects the joint configuration of
  classifier, threshold, and pre/post processing; component swaps will
  shift the operating point
