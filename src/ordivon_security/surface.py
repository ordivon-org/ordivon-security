from __future__ import annotations

from dataclasses import dataclass

from ordivon_security._canonical import JsonObject, validate_json


@dataclass(frozen=True, slots=True)
class SecuritySurfaceEntry:
    name: str
    tier: str
    module: str
    role: str
    stability: str

    def to_dict(self) -> JsonObject:
        value: JsonObject = {
            "name": self.name,
            "tier": self.tier,
            "module": self.module,
            "role": self.role,
            "stability": self.stability,
        }
        validate_json(value)
        return value


_SURFACE: tuple[SecuritySurfaceEntry, ...] = (
    SecuritySurfaceEntry(
        "RangeSession",
        "constitution",
        "ordivon_security.range",
        "Security projection over a persistent contested world without mandatory ticks.",
        "reusable-experimental",
    ),
    SecuritySurfaceEntry(
        "RangeAuthority",
        "constitution",
        "ordivon_security.range",
        "Exact principal/Actor zone and capability grant; boundary labels are profile-defined.",
        "reusable-experimental",
    ),
    SecuritySurfaceEntry(
        "RangeEffectRequest",
        "constitution",
        "ordivon_security.range",
        "Typed consequential intent envelope; admission and execution remain separate facts.",
        "reusable-experimental",
    ),
    SecuritySurfaceEntry(
        "RangeIntentContext / RangeIntentDecision",
        "constitution",
        "ordivon_security.actors.autonomous",
        "Agent-first observation/objective/authority to zero-or-more effect-request contract.",
        "candidate-reusable",
    ),
    SecuritySurfaceEntry(
        "EvidenceRecorder",
        "constitution",
        "ordivon_security.evidence",
        "Bounded experiment evidence with separated actor/management/sensor/world-truth authority.",
        "reusable",
    ),
    SecuritySurfaceEntry(
        "SynchronousContestProfile",
        "profile",
        "ordivon_security.range",
        "Deterministic synchronous comparison profile over a RangeSession.",
        "accepted-profile",
    ),
    SecuritySurfaceEntry(
        "ContestRunner",
        "profile",
        "ordivon_security.contest",
        "Tick/proposal/admission/resolution runner for bounded reproducible Contests.",
        "accepted-profile",
    ),
    SecuritySurfaceEntry(
        "Software Evaluation",
        "profile",
        "ordivon_security.evaluation",
        "SampleVault, Guardian, static/dynamic software-evaluation contracts and Windows profiles.",
        "accepted-profile",
    ),
    SecuritySurfaceEntry(
        "CAGE team-plan actor",
        "profile",
        "ordivon_security.actors",
        "Fresh-per-tick allowed-action team-plan control used by the current CAGE adapter.",
        "accepted-profile",
    ),
    SecuritySurfaceEntry(
        "DeepSeek Range-intent driver",
        "integration",
        "ordivon_security.integrations",
        "Harness-backed AF2 decision producer; cognition remains owned by Harness/Provider.",
        "experimental-integration",
    ),
    SecuritySurfaceEntry(
        "Host/Runtime actor adapters",
        "integration",
        "ordivon_security.integrations",
        "P0-B/P0-C integration apparatus binding foreign Host/Runtime evidence to Security trials.",
        "experimental-integration",
    ),
    SecuritySurfaceEntry(
        "World destination adapters",
        "integration",
        "ordivon_security.world_boundary",
        "Message/resource/entity destination admission experiments; foreign claims are not promoted to truth.",
        "experimental-integration",
    ),
    SecuritySurfaceEntry(
        "IF0–IF2 intent convergence research",
        "research-apparatus",
        "ordivon_security.cli_deliberation_before_authority_if2_acceptance",
        "IF0/IF1 falsify finalization/readback as sufficient cognition-convergence mechanisms; IF2 accepts no-effect deliberation before authority in the exact AC2 mismatch consumer.",
        "accepted-research-with-falsifiers",
    ),
    SecuritySurfaceEntry(
        "AC2 verifiable disclosure / intent convergence falsifier",
        "research-apparatus",
        "ordivon_security.cli_verifiable_disclosure_ac2_acceptance",
        "Selective authoritative disclosure resolves epistemic ambiguity but exposes non-convergence between final Agent reasoning and Tool-authoritative pending intent.",
        "falsified-research",
    ),
    SecuritySurfaceEntry(
        "AC1 incentive communication falsifier",
        "research-apparatus",
        "ordivon_security.cli_incentive_communication_ac1_acceptance",
        "Frozen-source cheap-talk experiment showing public common aligned incentives still do not guarantee strategic credibility; first B-to-A replies observed.",
        "falsified-research",
    ),
    SecuritySurfaceEntry(
        "AC0 autonomous communication falsifier",
        "research-apparatus",
        "ordivon_security.cli_autonomous_communication_ac0_acceptance",
        "Two-Agent cheap-talk coordination falsifier with exact actor-specific message projection and no Trust/mailbox primitive.",
        "falsified-research",
    ),
    SecuritySurfaceEntry(
        "EC1 derived-evidence applicability",
        "research-apparatus",
        "research/experiments/ec1-derived-evidence-freshness/applicability.py",
        "Accepted source-evolution experiment separating projection integrity from current exact-dependency applicability without clocks or TTL.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "EC0 externalized evidence computation",
        "research-apparatus",
        "research/experiments/ec0-evidence-computation/reducer.py",
        "Accepted standalone computation experiment reproducing AE3-C derived facts from exact Git-owned fixtures under Runtime source-state commitment.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "AE3-C verifiable evidence-reduction consumer",
        "research-apparatus",
        "ordivon_security.cli_adversarial_epistemics_ae3c_acceptance",
        "Accepted experiment using an exact reconstructable factual projection to remove raw-history aggregation friction without creating Trust or current truth.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "AE3-B raw-source-history epistemics falsifier",
        "research-apparatus",
        "ordivon_security.cli_adversarial_epistemics_ae3b_acceptance",
        "Falsified experiment showing raw adjudicated history in ordinary context does not guarantee stable evidence reduction or effect intent.",
        "falsified-research",
    ),
    SecuritySurfaceEntry(
        "AE3 no-adjudication epistemics consumer",
        "research-apparatus",
        "ordivon_security.cli_adversarial_epistemics_ae3_acceptance",
        "Counterfactual ambiguity experiment separating bounded consequence choice from hidden-world truth and risk-optimality claims.",
        "accepted-research-with-falsifier",
    ),
    SecuritySurfaceEntry(
        "AE2 conflicting-observations epistemics consumer",
        "research-apparatus",
        "ordivon_security.cli_adversarial_epistemics_ae2_acceptance",
        "Counterfactual evidence-conflict experiment separating independent sensor provenance from authoritative current world truth.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "AE1 delayed-truth epistemics consumer",
        "research-apparatus",
        "ordivon_security.cli_adversarial_epistemics_ae1_acceptance",
        "Counterfactual delayed-truth experiment with autonomous false claim, costly pending UNKNOWN, and shared pre-truth Agent policy.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "AE0 adversarial epistemics consumer",
        "research-apparatus",
        "ordivon_security.cli_adversarial_epistemics_ae0_acceptance",
        "Autonomous sender manipulation plus byte-identical partial receiver evidence and explicit information acquisition.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "AF3 deception consumer",
        "research-apparatus",
        "ordivon_security.cli_agent_first_deception_acceptance",
        "First higher-order AF2 consumer separating communicated claim from independent truth.",
        "accepted-research",
    ),
    SecuritySurfaceEntry(
        "Acceptance runners",
        "research-apparatus",
        "ordivon_security.cli_*_acceptance",
        "Fault injectors and physical acceptance orchestration retaining exact historical evidence.",
        "research-only",
    ),
    SecuritySurfaceEntry(
        "Windows P1 probes/canaries",
        "research-apparatus",
        "ordivon_security.cli_windows_kvm_p1_*",
        "Case-specific build, probe, observer and orchestration apparatus.",
        "research-only",
    ),
)


def security_surface_manifest() -> JsonObject:
    value: JsonObject = {
        "schemaVersion": 1,
        "kind": "ordivon.security.agent-first-surface",
        "compatibilityFacade": {
            "module": "ordivon_security.api",
            "maturity": "mixed",
            "rule": "Presence in the compatibility facade does not imply constitutional or stable status.",
        },
        "entries": [entry.to_dict() for entry in _SURFACE],
        "rules": [
            "Profiles do not become constitutional law merely because they are accepted.",
            "Research apparatus may consume reusable substrate; reusable substrate must not depend on experiment chronology.",
            "Foreign Host/Harness/Runtime/World projections remain evidence owned by their source systems.",
        ],
    }
    validate_json(value)
    return value


__all__ = ["SecuritySurfaceEntry", "security_surface_manifest"]
