from __future__ import annotations

import argparse
import hashlib
import json
import signal
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from types import FrameType
from typing import Any

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.evaluation import (
    AuthorityManifest,
    EnvironmentIdentity,
    EvaluationRunner,
    EvaluationSpec,
    GuardianPolicy,
    ObservationPlan,
    SampleVault,
)
from ordivon_security.evaluation.evidence import verify_evaluation_evidence
from ordivon_security.evaluation.windows_kvm import (
    WindowsKvmEvaluationBackend,
    WindowsKvmProviderConfig,
)

_CARRIERS = (
    ("native", 0),
    ("powershell", 1),
    ("wsh-vbscript", 2),
    ("msi-installed-custom-action", 3),
)
_FIXTURE_PREFIX = "ordivon-ca1-carrier-probe-v1"
_PRODUCT_CODE = "D1C2146B-8AD8-4C5E-B782-F414717A1011"
_UPGRADE_CODE = "8875E099-F16C-49A6-AE66-AF14EE121011"
_PROHIBITED_NETWORK_IMPORTS = (
    "ws2_32",
    "wininet",
    "winhttp",
    "urlmon",
    "dnsapi",
    "iphlpapi",
    "internetopen",
)


class _RuntimeCancellation(RuntimeError):
    """Translate Runtime termination into controlled Evaluation cleanup."""


@dataclass(frozen=True, slots=True)
class _BuiltAssets:
    effect_path: Path
    effect_digest: str
    effect_byte_length: int
    msi_path: Path
    msi_digest: str
    msi_byte_length: int
    header_path: Path
    provider_identity: JsonObject


@contextmanager
def _translate_runtime_cancellation() -> Iterator[None]:
    previous_handlers = {
        signal_number: signal.getsignal(signal_number)
        for signal_number in (signal.SIGTERM, signal.SIGINT)
    }

    def request_cancellation(signal_number: int, _frame: FrameType | None) -> None:
        raise _RuntimeCancellation(f"Runtime cancellation requested by signal {signal_number}")

    for signal_number in previous_handlers:
        signal.signal(signal_number, request_cancellation)
    try:
        yield
    finally:
        for signal_number, previous_handler in previous_handlers.items():
            signal.signal(signal_number, previous_handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the CA1 same-effect Windows carrier matrix across native, PowerShell, "
            "WSH/VBScript, and MSI installed-custom-action carriers. All treatments are "
            "maintained benign fixtures in a no-NIC disposable Windows KVM Range."
        )
    )
    parser.add_argument("--base-manifest", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--vault", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--memory-mib", type=int, default=5120)
    parser.add_argument("--vcpus", type=int, default=4)
    parser.add_argument("--run-index-base", type=int, default=0)
    return parser


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _safe_dependency(path: Path, label: str) -> Path:
    resolved = path.resolve()
    if resolved.is_symlink() or not resolved.is_file():
        raise ValueError(f"CA1 {label} is missing or unsafe: {resolved}")
    return resolved


def _tool_identity(path: Path, version_args: Sequence[str]) -> JsonObject:
    output = subprocess.run(
        [str(path), *version_args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    ).stdout.splitlines()
    return {
        "path": str(path),
        "sha256": _digest_bytes(path.read_bytes()),
        "version": output[0] if output else "unknown",
    }


def _assert_no_network_imports(path: Path, objdump: Path) -> None:
    imports = subprocess.run(
        [str(objdump), "-p", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    ).stdout.lower()
    matches = sorted(value for value in _PROHIBITED_NETWORK_IMPORTS if value in imports)
    if matches:
        raise ValueError(f"CA1 maintained fixture imports prohibited network APIs: {matches}")


def _compile_effect(root: Path, compiler: Path, objdump: Path) -> tuple[Path, str, int]:
    source = _safe_dependency(
        Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "ca1_effect_payload.c"
                )
            )
        ),
        "effect source",
    )
    output = root / "effect.exe"
    subprocess.run(
        [
            str(compiler),
            "-municode",
            "-Os",
            "-s",
            "-static",
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
            "-o",
            str(output),
            str(source),
            "-ladvapi32",
        ],
        check=True,
        timeout=120,
    )
    _assert_no_network_imports(output, objdump)
    raw = output.read_bytes()
    return output, hashlib.sha256(raw).hexdigest(), len(raw)


def _msi_wxs(effect_path: Path) -> str:
    source = str(effect_path).replace("&", "&amp;").replace("'", "&apos;")
    marker = r"C:\ProgramData\Ordivon\ca1\effect.marker"
    evidence = r"C:\ProgramData\Ordivon\ca1\effect-evidence.json"
    return rf"""<?xml version='1.0' encoding='utf-8'?>
<Wix xmlns='http://schemas.microsoft.com/wix/2006/wi'>
  <Product Name='Ordivon CA1 Same Effect MSI' Id='{_PRODUCT_CODE}'
           UpgradeCode='{_UPGRADE_CODE}' Language='1033' Codepage='1252'
           Version='1.0.0' Manufacturer='Ordivon'>
    <Package Id='*' InstallerVersion='500' Compressed='yes' InstallScope='perMachine'/>
    <Media Id='1' Cabinet='ca1.cab' EmbedCab='yes'/>
    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='ProgramFiles64Folder'>
        <Directory Id='INSTALLDIR' Name='OrdivonCA1'>
          <Component Id='PayloadComponent' Guid='2A127088-E29C-4CC4-9857-D0C792111011' Win64='yes'>
            <File Id='EffectEXE' Name='effect.exe' Source='{source}' KeyPath='yes'/>
          </Component>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id='Complete' Level='1'><ComponentRef Id='PayloadComponent'/></Feature>
    <CustomAction Id='RunEffect' FileKey='EffectEXE'
      ExeCommand='&quot;{marker}&quot; &quot;{evidence}&quot;'
      Execute='immediate' Return='check'/>
    <InstallExecuteSequence>
      <Custom Action='RunEffect' After='InstallFinalize'>NOT Installed</Custom>
    </InstallExecuteSequence>
  </Product>
</Wix>
"""


def _build_msi(
    root: Path, wixl: Path, msiinfo: Path, effect_path: Path
) -> tuple[Path, str, int, JsonObject]:
    wxs = root / "ca1.wxs"
    msi = root / "carrier.msi"
    wxs.write_text(_msi_wxs(effect_path), encoding="utf-8")
    subprocess.run(
        [str(wixl), "--arch", "x64", "-o", str(msi), str(wxs)],
        check=True,
        cwd=root,
        timeout=120,
    )
    custom_action = subprocess.run(
        [str(msiinfo), "export", str(msi), "CustomAction"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
    ).stdout
    sequence = subprocess.run(
        [str(msiinfo), "export", str(msi), "InstallExecuteSequence"],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
        timeout=30,
    ).stdout
    if "RunEffect\t18\tEffectEXE" not in custom_action:
        raise ValueError(
            "CA1 MSI does not contain the expected installed-EXE Type 18 custom action"
        )
    if "RunEffect\tNOT Installed" not in sequence:
        raise ValueError("CA1 MSI custom action is not bound to first installation")
    raw = msi.read_bytes()
    return (
        msi,
        hashlib.sha256(raw).hexdigest(),
        len(raw),
        {
            "productCode": "{" + _PRODUCT_CODE + "}",
            "upgradeCode": "{" + _UPGRADE_CODE + "}",
            "customActionType": 18,
            "customActionSource": "EffectEXE",
            "customActionCondition": "NOT Installed",
            "installedPath": r"C:\Program Files\OrdivonCA1\effect.exe",
        },
    )


def _array_literal(name: str, value: bytes) -> str:
    lines = [f"static const unsigned char {name}[] = {{"]
    for offset in range(0, len(value), 16):
        chunk = value[offset : offset + 16]
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    lines.append("};")
    return "\n".join(lines)


def _write_embedded_header(
    path: Path,
    effect: bytes,
    effect_digest: str,
    msi: bytes,
    msi_digest: str,
) -> None:
    content = "\n".join(
        [
            "#ifndef ORDIVON_CA1_EMBEDDED_ASSETS_H",
            "#define ORDIVON_CA1_EMBEDDED_ASSETS_H",
            _array_literal("CA1_EFFECT_EXE_BYTES", effect),
            f"#define CA1_EFFECT_EXE_BYTE_LENGTH {len(effect)}ULL",
            f'#define CA1_EFFECT_EXE_SHA256 "{effect_digest}"',
            _array_literal("CA1_MSI_BYTES", msi),
            f"#define CA1_MSI_BYTE_LENGTH {len(msi)}ULL",
            f'#define CA1_MSI_SHA256 "{msi_digest}"',
            "#endif",
            "",
        ]
    )
    path.write_text(content, encoding="utf-8")


def _build_assets(root: Path) -> tuple[_BuiltAssets, JsonObject]:
    compiler = _safe_dependency(Path("/usr/bin/x86_64-w64-mingw32-gcc"), "compiler")
    objdump = _safe_dependency(Path("/usr/bin/x86_64-w64-mingw32-objdump"), "objdump")
    wixl = _safe_dependency(Path("/usr/bin/wixl"), "wixl")
    msiinfo = _safe_dependency(Path("/usr/bin/msiinfo"), "msiinfo")
    effect_path, effect_digest, effect_length = _compile_effect(root, compiler, objdump)
    msi_path, msi_digest, msi_length, msi_contract = _build_msi(root, wixl, msiinfo, effect_path)
    header_path = root / "ca1_embedded_assets.h"
    _write_embedded_header(
        header_path,
        effect_path.read_bytes(),
        effect_digest,
        msi_path.read_bytes(),
        msi_digest,
    )
    provider_identity = {
        "compiler": _tool_identity(compiler, ("--version",)),
        "objdump": _tool_identity(objdump, ("--version",)),
        "wixl": _tool_identity(wixl, ("--version",)),
        "msiinfo": _tool_identity(msiinfo, ("--version",)),
        "msiContract": msi_contract,
    }
    return (
        _BuiltAssets(
            effect_path=effect_path,
            effect_digest=effect_digest,
            effect_byte_length=effect_length,
            msi_path=msi_path,
            msi_digest=msi_digest,
            msi_byte_length=msi_length,
            header_path=header_path,
            provider_identity=provider_identity,
        ),
        provider_identity,
    )


def _compile_probe(
    root: Path,
    carrier: str,
    carrier_index: int,
    assets: _BuiltAssets,
) -> tuple[Path, JsonObject]:
    source = _safe_dependency(
        Path(
            str(
                files("ordivon_security").joinpath(
                    "resources", "windows_kvm", "ca1_carrier_probe.c"
                )
            )
        ),
        "carrier-probe source",
    )
    compiler = _safe_dependency(Path("/usr/bin/x86_64-w64-mingw32-gcc"), "compiler")
    objdump = _safe_dependency(Path("/usr/bin/x86_64-w64-mingw32-objdump"), "objdump")
    output = root / f"ca1-carrier-{carrier}.exe"
    subprocess.run(
        [
            str(compiler),
            "-municode",
            "-Os",
            "-s",
            "-static",
            "-Wl,--dynamicbase",
            "-Wl,--nxcompat",
            f"-DCA1_CARRIER={carrier_index}",
            "-I",
            str(assets.header_path.parent),
            "-o",
            str(output),
            str(source),
            "-lbcrypt",
        ],
        check=True,
        timeout=120,
    )
    _assert_no_network_imports(output, objdump)
    raw = output.read_bytes()
    return (
        output,
        {
            "fixtureId": f"{_FIXTURE_PREFIX}:{carrier}",
            "carrier": carrier,
            "sourceDigest": _digest_bytes(source.read_bytes()),
            "fixtureDigest": _digest_bytes(raw),
            "fixtureByteLength": len(raw),
            "sameEffectDigest": "sha256:" + assets.effect_digest,
            "sameEffectByteLength": assets.effect_byte_length,
            "msiDigest": "sha256:" + assets.msi_digest,
            "msiByteLength": assets.msi_byte_length,
            "networkImportMatches": [],
            "thirdPartySampleExecution": False,
        },
    )


def _load_fixture_result(evidence_path: Path) -> JsonObject:
    verify_evaluation_evidence(evidence_path)
    manifest = json.loads((evidence_path / "bundle-manifest.json").read_text(encoding="utf-8"))
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("CA1 evidence bundle artifact manifest is invalid")
    matches = [
        item
        for item in artifacts
        if isinstance(item, dict) and item.get("kind") == "benign-fixture-result"
    ]
    if len(matches) != 1:
        raise ValueError("CA1 evidence bundle must contain one benign fixture result")
    relative = matches[0].get("path")
    if not isinstance(relative, str):
        raise ValueError("CA1 fixture artifact path is invalid")
    value: Any = json.loads((evidence_path / relative).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("CA1 fixture result must be an object")
    return value


def _run_carrier(
    *,
    carrier: str,
    run_index: int,
    fixture_path: Path,
    compilation: JsonObject,
    args: argparse.Namespace,
    vault: SampleVault,
) -> JsonObject:
    sample = vault.import_path(
        fixture_path,
        media_type="application/vnd.microsoft.portable-executable",
    )
    fixture_id = f"{_FIXTURE_PREFIX}:{carrier}"
    compilation_digest = canonical_digest(compilation)
    carrier_index = dict(_CARRIERS)[carrier]
    carrier_state = args.state_root / f"c{carrier_index}"
    config = WindowsKvmProviderConfig(
        state_root=carrier_state,
        base_manifest_path=args.base_manifest,
        admitted_sample_digest=sample.sha256,
        fixture_attestation_digest=compilation_digest,
        admitted_fixture_id=fixture_id,
        fixture_runtime_ms=3 * 60 * 1000,
        memory_mib=args.memory_mib,
        vcpu_count=args.vcpus,
    )
    backend = WindowsKvmEvaluationBackend(config)
    guardian = GuardianPolicy(
        policy_id=f"guardian-policy:ca1:{carrier}",
        revision="1",
        network_mode="deny-all",
        max_runtime_ms=10 * 60 * 1000,
        max_memory_mib=args.memory_mib,
        max_processes=96,
        max_artifact_bytes=128 * 1024 * 1024,
        terminate_on=("network-device", "runtime-limit", "operator-stop"),
    )
    observation = ObservationPlan(
        plan_id=f"observation-plan:ca1:{carrier}",
        revision="1",
        channels=("sample", "management", "observer", "guardian", "world-truth"),
        capture_memory="never",
        max_event_bytes=1024 * 1024,
    )
    identity = backend.execution_identity
    environment = EnvironmentIdentity(
        environment_id=f"environment:ca1:{carrier}",
        provider_id=backend.provider_id,
        provider_revision="1",
        image_digest=backend.base.environment_image_digest,
        configuration_digest=canonical_digest(identity),
        guardian_policy_digest=guardian.digest,
        observation_plan_digest=observation.digest,
    )
    authority = AuthorityManifest(
        authority_id=f"authority:ca1:{carrier}",
        revision="1",
        sample_digest=sample.sha256,
        operator_id="operator:local",
        authorization_basis=(
            "CA1 maintained benign same-effect carrier experiment in a disposable no-NIC "
            "owned Windows KVM Range. The fixture may only exercise the declared carrier and "
            "write its bounded local marker/evidence before cleanup."
        ),
        permitted_environment_ids=(environment.environment_id,),
        permitted_actions=("execute-benign-fixture",),
        prohibited_actions=(
            "network-access",
            "execute-third-party-sample",
            "credential-collection",
            "target-expansion",
        ),
        max_runtime_ms=guardian.max_runtime_ms,
        allow_network=False,
        metadata={
            "ca1Carrier": carrier,
            "sameSemanticEffect": "ca1-same-effect-v1",
            "fixtureCompilation": compilation,
        },
    )
    spec = EvaluationSpec(
        evaluation_id=f"evaluation:ca1:{carrier}",
        revision="1",
        sample=sample,
        authority=authority,
        environment=environment,
        guardian_policy=guardian,
        observation_plan=observation,
        requested_actions=("execute-benign-fixture",),
        metadata={
            "fixtureId": fixture_id,
            "ca1Carrier": carrier,
            "sameSemanticEffect": "ca1-same-effect-v1",
            "fixtureCompilation": compilation,
            "fixtureCompilationDigest": compilation_digest,
            "unknownSampleExecution": False,
            "thirdPartySampleExecution": False,
        },
    )
    with _translate_runtime_cancellation():
        result = EvaluationRunner(backend, vault, evidence_root=args.evidence).run(
            spec,
            run_index=run_index,
        )
    fixture = _load_fixture_result(Path(result.evidence_path))
    return {
        "carrier": carrier,
        "evaluation": result.to_dict(),
        "fixtureResult": fixture,
        "fixtureCompilation": compilation,
    }


def _compare(treatments: list[JsonObject]) -> JsonObject:
    completed = [
        item
        for item in treatments
        if isinstance(item.get("fixtureResult"), dict)
        and item["fixtureResult"].get("completed") is True
    ]
    effects = {
        str(item["fixtureResult"].get("semanticEffectId"))
        for item in completed
        if isinstance(item.get("fixtureResult"), dict)
    }
    effect_digests = {
        str(item["fixtureResult"].get("effectPayloadSha256"))
        for item in completed
        if isinstance(item.get("fixtureResult"), dict)
    }
    parent_matches = {
        str(item.get("carrier")): bool(item["fixtureResult"].get("expectedParentObserved"))
        for item in completed
    }
    office_presence = {
        bool(item["fixtureResult"].get("officeWordProviderPresent")) for item in completed
    }
    msi = next(
        (item for item in completed if item.get("carrier") == "msi-installed-custom-action"), None
    )
    powershell = next((item for item in completed if item.get("carrier") == "powershell"), None)
    return {
        "completedCarrierCount": len(completed),
        "allFourCarriersCompleted": len(completed) == len(_CARRIERS),
        "sameSemanticEffectAcrossCompleted": effects == {"ca1-same-effect-v1"},
        "samePayloadBytesAcrossCompleted": len(effect_digests) == 1 and len(completed) > 0,
        "expectedParentObservedByCarrier": parent_matches,
        "officeWordProviderPresenceConsistent": len(office_presence) <= 1,
        "officeWordProviderPresent": next(iter(office_presence))
        if len(office_presence) == 1
        else None,
        "powershellRestrictedGateObserved": (
            powershell is not None
            and bool(powershell["fixtureResult"].get("powershellRestrictedGateStarted"))
        ),
        "powershellRestrictedGateBlocked": (
            powershell is not None
            and bool(powershell["fixtureResult"].get("powershellRestrictedBlocked"))
        ),
        "msiIntroducedInstallerLog": (
            msi is not None and bool(msi["fixtureResult"].get("msiLogPresent"))
        ),
        "msiCleanupVerified": (
            msi is not None
            and bool(msi["fixtureResult"].get("msiInstalledPayloadRemoved"))
            and int(msi["fixtureResult"].get("msiUninstallExitCode", -1)) == 0
        ),
        "interpretationBoundary": (
            "Carrier identity is decision-relevant only through observed changes in availability, "
            "policy/provenance gate, authority/process lineage, telemetry/exposure, latency, "
            "persistent footprint, or cleanup. Same-effect success alone does not create a new "
            "semantic capability domain."
        ),
    }


def main() -> None:
    args = build_parser().parse_args()
    args.state_root.mkdir(parents=True, exist_ok=True)
    args.vault.mkdir(parents=True, exist_ok=True)
    args.evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ordivon-ca1-") as raw_root:
        build_root = Path(raw_root)
        assets, provider_identity = _build_assets(build_root)
        vault = SampleVault(args.vault, max_sample_bytes=64 * 1024 * 1024)
        treatments: list[JsonObject] = []
        fixture_compilations: list[JsonObject] = []
        for offset, (carrier, carrier_index) in enumerate(_CARRIERS):
            fixture_path, compilation = _compile_probe(build_root, carrier, carrier_index, assets)
            fixture_compilations.append(compilation)
            treatments.append(
                _run_carrier(
                    carrier=carrier,
                    run_index=args.run_index_base + offset,
                    fixture_path=fixture_path,
                    compilation=compilation,
                    args=args,
                    vault=vault,
                )
            )
        comparison = _compare(treatments)
        payload: JsonObject = {
            "schemaVersion": 1,
            "kind": "ordivon.security.ca1-carrier-matrix",
            "researchQuestion": (
                "When one exact maintained semantic effect/payload is held constant, which "
                "execution-carrier properties materially differ across native, PowerShell, "
                "WSH/VBScript, and MSI installed-custom-action realizations?"
            ),
            "baseManifest": str(args.base_manifest.resolve()),
            "providerIdentity": provider_identity,
            "sameEffect": {
                "effectId": "ca1-same-effect-v1",
                "sha256": "sha256:" + assets.effect_digest,
                "byteLength": assets.effect_byte_length,
            },
            "sameMsi": {
                "sha256": "sha256:" + assets.msi_digest,
                "byteLength": assets.msi_byte_length,
            },
            "fixtureCompilations": fixture_compilations,
            "treatments": treatments,
            "comparison": comparison,
            "limitations": [
                (
                    "The experiment uses maintained benign fixtures only; it does not execute "
                    "malware or third-party code."
                ),
                (
                    "Windows Script Host is used as the physical hosted-script contrast because "
                    "the accepted base is not assumed to contain Microsoft Office."
                ),
                (
                    "Exact Office/VBA carrier behavior remains a provider-specific consumer only "
                    "if an accepted Office-capable Range is later justified."
                ),
                (
                    "PowerShell ExecutionPolicy is observed as a carrier policy gate, not "
                    "elevated to a Security authority boundary."
                ),
                (
                    "MSI custom-action success establishes installer-specific carrier semantics "
                    "for this fixture, not general MSI safety or attacker capability."
                ),
            ],
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if args.output is not None:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded, encoding="utf-8")
        print(encoded, end="")
        if not comparison.get("allFourCarriersCompleted"):
            raise SystemExit(2)
        if not comparison.get("sameSemanticEffectAcrossCompleted"):
            raise SystemExit(3)
        if not comparison.get("samePayloadBytesAcrossCompleted"):
            raise SystemExit(4)


if __name__ == "__main__":
    main()
