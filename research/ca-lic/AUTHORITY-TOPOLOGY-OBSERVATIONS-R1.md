# CA-LIC R1 — Real-system authority-topology observations

Retrieved from vendor/official documentation on 2026-08-15. This file is an
**observation matrix**, not a reverse-engineering record. It intentionally
contains no third-party bypass procedure, patch location, or executable sample.

## Comparison axes

For each system ask the same questions:

1. Is the protected implementation shipped to the client?
2. Is a secret/key/token required, and where does it live?
3. Where is entitlement authority evaluated?
4. Does the external authority merely answer `yes/no`, or perform a necessary operation?
5. What offline semantics are explicitly supported?
6. Can a result be independently distinguished from a local fake?
7. Which CA-LIC topology does the system most resemble?

## Matrix

| System | Protected implementation | Authority / carrier | Offline semantics | External work required for protected capability? | CA-LIC reading |
| --- | --- | --- | --- | --- | --- |
| TouchDesigner | Desktop capability is primarily local; license tier changes available features | local keys, CodeMeter USB dongle, network-distributed dongle license, floating cloud license | varies by carrier; local/dongle paths exist | dongle/cloud can externalize authorization, but many gated features still execute locally | V2/V3/V6 with V7-like external carrier; not automatically V8 |
| JetBrains IDE + License Vault | IDE implementation is local | account / License Vault / floating server / offline activation code | License Vault docs state up to 48h disconnected if the IDE is not restarted; restart while disconnected immediately loses Vault access | Vault grants entitlement; IDE capability remains local | clean V6 lease example |
| Adobe Acrobat / Creative Cloud desktop | Acrobat Pro/Standard share a desktop installer and behavior/features are provisioned by entitlement | Named User Licensing / Admin Console; Feature Restricted Licensing for restricted networks | named-user licensing requires periodic connectivity; Adobe documents bounded offline windows and FRL for restricted/offline deployments | desktop capability mostly local; cloud services are separately remote | V6 for desktop entitlement + V8 for genuinely cloud-hosted services |
| iLok | protected application is installed locally | host computer, iLok USB, or iLok Cloud session; publisher chooses valid locations | USB/host permit local use; Cloud requires a consistent internet connection | external carrier authorizes locally installed software; Cloud/USB are not the protected application itself | V7-like external authorizer with local capability, not V8 |
| Denuvo Anti-Piracy / Anti-Tamper | protected game remains local | platform ownership validation + hardware-bound token + anti-tamper/hardware binding | Irdeto advertises one-time activation / no always-on connection for Anti-Tamper | ownership/token authority is external at activation; gameplay remains local | V2/V4/V6 + explicit H5 attack-economics strategy |
| Apple Secure Enclave + App Attest | app remains local; selected private-key operations occur in isolated hardware | Secure Enclave key + Apple attestation + application server | device-local Secure Enclave operations do not require exporting the private key | yes: the required private-key operation is performed by the Secure Enclave; App Attest lets a server validate an app instance | strong V7 example; external primitive changes the trust boundary |
| AWS KMS | caller application is local/remote, but KMS key capability remains service/HSM-side | IAM/key policy + KMS service + HSM-resident key material | cryptographic use requires KMS availability unless the application uses a separately materialized data key/cache | yes: plaintext KMS key material stays inside HSMs and cryptographic operations require KMS calls | strong V8/V7 remote-capability example |

## Official sources

### TouchDesigner / Derivative

- Licensing: https://docs.derivative.ca/Licensing
- Products / feature tiers: https://derivative.ca/solr/touchdesigner-products
- License Dongle / network distribution: https://docs.derivative.ca/License_Dongle
- Privacy / dongle-bound private components: https://derivative.ca/UserGuide/Privacy

Stable observation: TouchDesigner is a useful **hybrid**. License authority can
move from a local key to a dongle/network/cloud carrier, but that does not imply
that every protected feature becomes a remote capability.

### JetBrains

- IntelliJ registration / offline activation / license server: https://www.jetbrains.com/help/idea/register.html
- License Vault activation and offline window: https://www.jetbrains.com/help/license-vault-cloud/Activating_a_license.html
- IDE Services activation: https://www.jetbrains.com/help/ide-services/Activating_a_license.html

Stable observation: a remote license service can deliberately issue a bounded
local right-to-run window. This is almost exactly ToyDesigner V6-R1 lease
semantics: more offline survivability implies more time before central revocation
can force a disconnected client to stop.

### Adobe

- Enterprise licensing overview: https://helpx.adobe.com/business/enterprise/plan-your-deployment/basic-concepts/licensing.html
- Acrobat deployment/licensing: https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/licensing.html
- Acrobat product tracks / entitlement behavior: https://www.adobe.com/devnet-docs/acrobatetk/tools/AdminGuide/whatsnewdc.html

Stable observation: one product family can mix local entitlement-gated desktop
capability and genuinely remote services. Treating the whole product as either
"local DRM" or "SaaS" loses the authority topology.

### iLok / PACE

- License Manager overview: https://help.ilok.com/ilm_overview.html
- License activation locations: https://help.ilok.com/faq_licenses.html
- iLok Cloud: https://help.ilok.com/faq_cloud.html
- iLok USB: https://help.ilok.com/faq_ilok.html

Stable observation: moving the license carrier to USB/cloud changes what the
attacker must control, but protected application code still being local means
this is not equivalent to server-side execution of the capability.

### Denuvo / Irdeto

- Anti-Piracy: https://irdeto.com/video-games/denuvo-anti-piracy/video-game-anti-piracy
- Anti-Tamper: https://irdeto.com/fight-piracy-with-denuvo-anti-tamper
- Anti-tamper design/economics discussion: https://irdeto.com/blog/pc-anti-tamper-technology-worries-tamed

Stable observation: the vendor itself frames the objective economically as
protecting the high-value launch window and uses hardware binding, DRM
shielding and anti-tamper to raise local attack cost. That is a real-world H5
example, not evidence of absolute client-side authority.

### Apple

- Secure Enclave key protection: https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave
- App Attest service: https://developer.apple.com/documentation/DeviceCheck/DCAppAttestService

Stable observation: the important shift is not stronger local obfuscation. The
app never receives the plaintext private key; it asks an isolated authority to
perform the operation. App Attest then allows a server to make a decision about
an app instance based on hardware-backed evidence.

### AWS KMS

- Data protection / HSM boundary: https://docs.aws.amazon.com/kms/latest/developerguide/data-protection.html
- Cryptographic operations: https://docs.aws.amazon.com/kms/latest/developerguide/kms-cryptography.html
- Key-store overview: https://docs.aws.amazon.com/kms/latest/developerguide/key-store-overview.html

Stable observation: AWS KMS is a clean contrast to V6. It does not merely say
"you may use this key" and then hand the root key to the client. The protected
key material stays inside the HSM boundary and callers invoke remote
cryptographic operations.

## Cross-system conclusions

### O1 — Carrier externalization is not capability externalization

USB dongles, cloud license sessions, hardware-bound tokens and remote license
servers can move *authorization evidence* out of a hostile process. If the
valuable implementation remains locally callable, the system is still
structurally different from V8.

### O2 — Offline convenience spends revocation freshness

JetBrains and Adobe explicitly expose bounded-offline licensing semantics. The
ToyDesigner V6-R1 TTL sweep shows the underlying structural trade: a locally
verifiable lease that remains valid for `T` offline units gives a revoked client
up to the same `T`-sized stale-authority window unless an external operation is
still required.

### O3 — External operation is the qualitative boundary change

Secure Enclave and AWS KMS keep a necessary secret/operation outside ordinary
client memory. A local patch can lie about UI state, but cannot by itself
produce the authority's valid operation/result.

### O4 — Output delivery is still irreversible

Even V8 cannot "take back" an already delivered plaintext/result. Externalized
capability makes **future computation** revocable; it does not make information
already released revocable.

### O5 — Authority identity becomes lifecycle state

Once results are signed by an external authority, provider/key rotation creates
a new continuity problem: new clients need the new trust anchor, while
historical verification may require retaining old authority identities.

## Boundary

These observations support CA-LIC theory only. They do not claim undocumented
implementation details and do not authorize active testing of the named
third-party products.
