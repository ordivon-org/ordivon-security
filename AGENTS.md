# Agent instructions

1. Keep capability elicitation and external consequence containment as separate concerns.
2. Do not claim attack, defense, escape, or containment results without exact Campaign and environment identity.
3. Do not add real targets, credentials, endpoints, exploit material, or personal network evidence to the repository.
4. Prefer schemas, fixtures, emulators, and owned range worlds over public-network experiments.
5. The evaluated Agent must not control the authoritative judge, observer, or lifecycle authority.
6. Preserve negative, failed, escaped, invalid, and inconclusive runs.
7. Reuse Ordivon Host, Runtime, Link, Edge, Game, and mature security tools; do not build shadow implementations without evidence.
8. Keep the Phase 0 module boundary explicit: `campaign.py` is the Security core
   contract; `ledger.py` is the authority ledger and replay; `bundle.py` is the
   evidence-bundle boundary; `bindings.py` and `coordinator.py` are
   component-neutral binding and fixed coordination; `process_ports.py` and
   `live_composition.py` are reference acceptance harnesses only.
9. Do not build a general JSON Schema engine, process manager, container or
   network substrate, telemetry stack, workflow system, or signature
   infrastructure in this repository. Use mature implementations and the
   owning Ordivon components.
10. Retain the current `campaign.py` compatibility validator for Phase 0, but
    freeze its vocabulary and scope. Any future replacement must first pass the
    existing valid/invalid fixture and transition conformance suite; do not
    expand it toward a general JSON Schema implementation.
11. Do not promote `process_ports.py` or `live_composition.py` into a Campaign
    engine, workflow DSL, Host, Runtime, or reusable process-management layer.
