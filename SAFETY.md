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

## Withheld Content

- The 100 attack scenarios in `data/hf_export/attack_scenarios.jsonl` are
  intentionally published to allow defensive replication. Each scenario is
  scoped to abstract attack patterns; none provides operational uplift for
  CBRN, financial, or critical-infrastructure attacks.
- Per-scenario LLM responses from the evaluation runs are tracked under
  `data/responses/` only at the level needed to reproduce the metric;
  response text is filtered for any inadvertent operational detail prior
  to release.
- Internal strategy documents (positioning, role-fit analyses) are
  gitignored and never appear in the public repository.

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
