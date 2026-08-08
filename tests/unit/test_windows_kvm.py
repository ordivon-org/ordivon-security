from __future__ import annotations

import hashlib
import json
import os
import signal
import stat
import subprocess
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ordivon_security._canonical import JsonObject, JsonValue, canonical_digest
from ordivon_security.cli_windows_kvm_acceptance import (
    _remove_compiled_fixture,
    _RuntimeCancellation,
    _translate_runtime_cancellation,
)
from ordivon_security.cli_windows_kvm_acceptance import (
    build_parser as build_acceptance_parser,
)
from ordivon_security.cli_windows_kvm_build import build_parser as build_base_parser
from ordivon_security.evaluation import (
    AuthorityManifest,
    EnvironmentIdentity,
    EvaluationInstance,
    EvaluationSpec,
    GuardianPolicy,
    ObservationPlan,
    SampleIdentity,
)
from ordivon_security.evaluation.windows_kvm import (
    _READONLY_MEDIA_FIXTURE_ID,
    _RUN_ACTION,
    _RUN_LABEL,
    WindowsKvmBaseImage,
    WindowsKvmEvaluationBackend,
    WindowsKvmProviderConfig,
    _pci_network_devices,
    _process_start_time,
    _terminate_pid,
    windows_kvm_qemu_arguments,
)
from ordivon_security.evaluation.windows_kvm_build import (
    _BUILD_LABEL,
    _CONFIG_LABEL,
    WindowsKvmBaseBuildConfig,
    _block_read_bytes,
    _create_fat_image,
    _validate_unattend,
    build_windows_kvm_base,
    windows_kvm_install_arguments,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class WindowsKvmP0Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.fake_qemu = self._tool("qemu-system-x86_64", "QEMU emulator version test")
        self.fake_qemu_img = self._tool("qemu-img", "qemu-img version test")
        self.fake_swtpm = self._tool("swtpm", "TPM emulator version test")
        self.fake_setpriv = self._tool("setpriv", "setpriv test")
        self.fake_mkfs = self._tool("mkfs.fat", "mkfs test")
        fake_mtools = self._tool("mtools", "mtools test")
        self.fake_mcopy = self.tools / "mcopy"
        self.fake_mdir = self.tools / "mdir"
        self.fake_mcopy.symlink_to(fake_mtools)
        self.fake_mdir.symlink_to(fake_mtools)
        self.firmware = self.root / "OVMF_CODE.fd"
        self.firmware.write_bytes(b"firmware")
        self.vars = self.root / "OVMF_VARS.fd"
        self.vars.write_bytes(b"vars")
        self.base_image = self.root / "base.qcow2"
        self.base_image.write_bytes(b"sealed-base-image")
        self.manifest_path = self.root / "base.manifest.json"
        environment_identity: JsonObject = {
            "sourceIsoDigest": "sha256:" + "1" * 64,
            "baseImageDigest": _digest(self.base_image),
            "baseVarsDigest": _digest(self.vars),
            "firmwareCodeDigest": _digest(self.firmware),
            "guestRunnerDigest": "sha256:" + "2" * 64,
            "windowsBuild": "10.0.26200.6584",
            "machine": "q35,accel=kvm,smm=on",
            "cpu": "host",
            "display": "VGA",
            "secureBoot": False,
            "smm": False,
            "network": "no-device",
            "tpm": "swtpm-2.0",
        }
        manifest = {
            "schemaVersion": 1,
            "kind": "ordivon.security.windows-kvm-base-image",
            "providerId": "provider:windows-kvm",
            "paths": {
                "baseImage": str(self.base_image),
                "baseVars": str(self.vars),
            },
            "digests": {
                "environmentImage": canonical_digest(environment_identity),
                "sourceIso": "sha256:" + "1" * 64,
                "baseImage": _digest(self.base_image),
                "baseVars": _digest(self.vars),
                "firmwareCode": _digest(self.firmware),
                "guestRunner": "sha256:" + "2" * 64,
            },
            "guest": {
                "status": "ready",
                "windowsBuild": "10.0.26200.6584",
            },
        }
        self.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.config = WindowsKvmProviderConfig(
            state_root=self.root / "state",
            base_manifest_path=self.manifest_path,
            qemu_path=self.fake_qemu,
            qemu_img_path=self.fake_qemu_img,
            swtpm_path=self.fake_swtpm,
            setpriv_path=self.fake_setpriv,
            mkfs_fat_path=self.fake_mkfs,
            mcopy_path=self.fake_mcopy,
            mdir_path=self.fake_mdir,
            firmware_code_path=self.firmware,
            run_user="root",
            run_group="root",
            admitted_sample_digest="sha256:" + "3" * 64,
            fixture_attestation_digest="sha256:" + "4" * 64,
            memory_mib=512,
            vcpu_count=1,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _tool(self, name: str, version: str) -> Path:
        path = self.tools / name
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def _spec(self, backend: WindowsKvmEvaluationBackend) -> EvaluationSpec:
        sample = SampleIdentity.create(
            sha256="sha256:" + "3" * 64,
            byte_length=18_944,
            media_type="application/vnd.microsoft.portable-executable",
            original_name="ordivon-benign-v1.exe",
        )
        guardian = GuardianPolicy(
            policy_id="guardian-policy:windows-kvm-test",
            revision="1",
            network_mode="deny-all",
            max_runtime_ms=600_000,
            max_memory_mib=512,
            max_processes=64,
            max_artifact_bytes=32 * 1024 * 1024,
            terminate_on=("network-device", "runtime-limit"),
        )
        observation = ObservationPlan(
            plan_id="observation-plan:windows-kvm-test",
            revision="1",
            channels=("sample", "management", "observer", "guardian", "world-truth"),
            capture_memory="never",
            max_event_bytes=512 * 1024,
        )
        environment = EnvironmentIdentity(
            environment_id="environment:windows-kvm-test",
            provider_id=backend.provider_id,
            provider_revision="1",
            image_digest=backend.base.environment_image_digest,
            configuration_digest=canonical_digest(backend.execution_identity),
            guardian_policy_digest=guardian.digest,
            observation_plan_digest=observation.digest,
        )
        authority = AuthorityManifest(
            authority_id="authority:windows-kvm-test",
            revision="1",
            sample_digest=sample.sha256,
            operator_id="operator:test",
            authorization_basis="Owned benign fixture for Provider acceptance.",
            permitted_environment_ids=(environment.environment_id,),
            permitted_actions=("execute-benign-fixture",),
            prohibited_actions=("network-access", "execute-unknown-sample"),
            max_runtime_ms=guardian.max_runtime_ms,
            allow_network=False,
        )
        return EvaluationSpec(
            evaluation_id="evaluation:windows-kvm-test",
            revision="1",
            sample=sample,
            authority=authority,
            environment=environment,
            guardian_policy=guardian,
            observation_plan=observation,
            requested_actions=("execute-benign-fixture",),
            metadata={
                "fixtureId": "ordivon-benign-v1",
                "fixtureCompilationDigest": "sha256:" + "4" * 64,
            },
        )

    def test_compiled_fixture_cleanup_is_idempotent(self) -> None:
        fixture_root = self.root / "fixtures"
        fixture_root.mkdir()
        fixture = fixture_root / "ordivon-benign-v1-run-99.exe"
        fixture.write_bytes(b"fixture")
        _remove_compiled_fixture(fixture, fixture_root)
        _remove_compiled_fixture(fixture, fixture_root)
        self.assertFalse(fixture.exists())
        self.assertFalse(fixture_root.exists())

    def test_runtime_termination_signal_becomes_controlled_cancellation(self) -> None:
        previous = signal.getsignal(signal.SIGTERM)
        with (
            self.assertRaisesRegex(_RuntimeCancellation, "signal"),
            _translate_runtime_cancellation(),
        ):
            os.kill(os.getpid(), signal.SIGTERM)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_cli_defaults_use_validated_local_resource_baseline(self) -> None:
        build_args = build_base_parser().parse_args(
            ["--source-iso", "source.iso", "--state-root", "state"]
        )
        acceptance_args = build_acceptance_parser().parse_args(
            [
                "--base-manifest",
                "base.manifest.json",
                "--state-root",
                "state",
                "--vault",
                "vault",
                "--evidence",
                "evidence",
            ]
        )
        self.assertEqual(build_args.memory_mib, 5120)
        self.assertEqual(acceptance_args.memory_mib, 5120)
        self.assertEqual(
            WindowsKvmBaseBuildConfig.__dataclass_fields__["memory_mib"].default,
            5120,
        )
        self.assertEqual(
            WindowsKvmProviderConfig.__dataclass_fields__["memory_mib"].default,
            5120,
        )

    def test_boot_media_progress_parser_is_device_scoped(self) -> None:
        value: JsonValue = [
            {"device": "osdisk", "stats": {"rd_bytes": 99}},
            {"device": "installcd", "stats": {"rd_bytes": 20 * 1024 * 1024}},
        ]
        self.assertEqual(_block_read_bytes(value, "installcd"), 20 * 1024 * 1024)
        self.assertEqual(_block_read_bytes(value, "missing"), 0)

    def test_base_manifest_loads_and_detects_tampering(self) -> None:
        base = WindowsKvmBaseImage.load(self.manifest_path)
        self.assertEqual(base.base_image_digest, _digest(self.base_image))
        self.assertEqual(base.windows_build, "10.0.26200.6584")
        self.base_image.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "base image digest differs"):
            WindowsKvmBaseImage.load(self.manifest_path)

    def test_runtime_qemu_topology_has_no_network_path(self) -> None:
        arguments = windows_kvm_qemu_arguments(
            config=self.config,
            overlay_path=self.root / "overlay.qcow2",
            vars_path=self.root / "vars-copy.fd",
            run_disk_path=self.root / "run.img",
            qmp_path=self.root / "qmp.sock",
            tpm_socket_path=self.root / "swtpm.sock",
            name="ordivon-test",
        )
        self.assertIn("-nic", arguments)
        self.assertEqual(arguments[arguments.index("-nic") + 1], "none")
        self.assertNotIn("-netdev", arguments)
        joined = " ".join(arguments).lower()
        self.assertNotIn("e1000", joined)
        self.assertNotIn("virtio-net", joined)
        self.assertIn("setpriv --reuid root --regid root --init-groups --", joined)
        self.assertIn("VGA", arguments)
        self.assertIn(
            f"usb-storage,drive=rundisk,bus=xhci.0,removable=on,serial={_RUN_LABEL}",
            arguments,
        )
        self.assertNotIn("usb-storage,drive=rundisk,bus=xhci.0,removable=off", joined)
        identity = WindowsKvmEvaluationBackend(self.config).execution_identity
        configuration = identity["configuration"]
        assert isinstance(configuration, dict)
        self.assertEqual(configuration["runDisk"], "usb-fat-writable-removable")
        self.assertEqual(configuration["runDiskLabel"], _RUN_LABEL)
        self.assertIs(configuration["runDiskReadOnly"], False)
        self.assertIs(configuration["runDiskRemovable"], True)

    def test_read_only_sample_media_config_requires_complete_identity(self) -> None:
        media = self.root / "sample-media.img"
        media.write_bytes(b"media")
        with self.assertRaisesRegex(ValueError, "identity is incomplete"):
            replace(self.config, read_only_sample_media_path=media)

    def test_read_only_sample_media_binding_is_exact(self) -> None:
        media = self.root / "sample-media.img"
        media.write_bytes(b"media")
        media_digest = _digest(media)
        config = replace(
            self.config,
            admitted_fixture_id=_READONLY_MEDIA_FIXTURE_ID,
            read_only_sample_media_path=media,
            read_only_sample_media_digest=media_digest,
            read_only_sample_media_serial="ORDIVON_P1",
            fixture_runtime_ms=900_000,
        )
        backend = WindowsKvmEvaluationBackend(config)
        spec = self._spec(backend)
        binding: JsonObject = {
            "digest": media_digest,
            "serial": "ORDIVON_P1",
            "readOnly": True,
            "sampleExecutionAuthorized": False,
        }
        bound = replace(
            spec,
            metadata={
                "fixtureId": _READONLY_MEDIA_FIXTURE_ID,
                "fixtureCompilationDigest": self.config.fixture_attestation_digest,
                "readOnlySampleMedia": binding,
            },
        )
        backend._validate_spec(bound)
        mismatched = replace(
            bound,
            metadata={
                **bound.metadata,
                "readOnlySampleMedia": {**binding, "sampleExecutionAuthorized": True},
            },
        )
        with self.assertRaisesRegex(ValueError, "media binding differs"):
            backend._validate_spec(mismatched)
        configuration = backend.execution_identity["configuration"]
        assert isinstance(configuration, dict)
        self.assertEqual(configuration["fixtureRuntimeMs"], 900_000)
        self.assertEqual(configuration["admittedFixtureId"], _READONLY_MEDIA_FIXTURE_ID)

    def test_read_only_media_verifier_waits_for_delayed_volume_enumeration(self) -> None:
        source = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "resources"
            / "windows_kvm"
            / "readonly_media_fixture.c.in"
        ).read_text(encoding="utf-8")
        self.assertIn("attempt < 120", source)
        self.assertIn("Sleep(1000)", source)
        self.assertIn("volumeWaitMs", source)
        self.assertIn("logicalDriveMask", source)

    def test_runtime_qemu_topology_attaches_declared_sample_media_read_only(self) -> None:
        media = self.root / "sample-media.img"
        media.write_bytes(b"media")
        arguments = windows_kvm_qemu_arguments(
            config=self.config,
            overlay_path=self.root / "overlay.qcow2",
            vars_path=self.root / "vars-copy.fd",
            run_disk_path=self.root / "run.img",
            qmp_path=self.root / "qmp.sock",
            tpm_socket_path=self.root / "swtpm.sock",
            name="ordivon-test",
            read_only_sample_media_path=media,
            read_only_sample_media_serial="ORDIVON_P1",
        )
        joined = " ".join(arguments)
        self.assertIn(f"file={media},if=none,format=raw,readonly=on", joined)
        self.assertIn(
            "usb-storage,drive=sampledisk,bus=xhci.0,removable=on,serial=ORDIVON_P1",
            joined,
        )
        self.assertNotIn("readonly=off", joined)

    def test_install_qemu_topology_has_no_network_path(self) -> None:
        source_iso = self.root / "source.iso"
        source_iso.write_bytes(b"iso")
        build_config = WindowsKvmBaseBuildConfig(
            state_root=self.root / "build-state",
            source_iso_path=source_iso,
            qemu_path=self.fake_qemu,
            qemu_img_path=self.fake_qemu_img,
            swtpm_path=self.fake_swtpm,
            setpriv_path=self.fake_setpriv,
            mkfs_fat_path=self.fake_mkfs,
            mcopy_path=self.fake_mcopy,
            firmware_code_path=self.firmware,
            firmware_vars_template_path=self.vars,
            run_user="root",
            run_group="root",
            memory_mib=512,
            vcpu_count=1,
            disk_size_gib=1,
        )
        arguments = windows_kvm_install_arguments(
            config=build_config,
            base_image_path=self.root / "build.qcow2",
            vars_path=self.root / "build-vars.fd",
            source_iso_path=source_iso,
            config_disk_path=self.root / "build-config.img",
            result_disk_path=self.root / "build-result.img",
            qmp_path=self.root / "build-qmp.sock",
            tpm_socket_path=self.root / "build-tpm.sock",
        )
        self.assertEqual(arguments[arguments.index("-nic") + 1], "none")
        self.assertNotIn("-netdev", arguments)
        self.assertIn("order=c,once=d,menu=off", arguments)
        self.assertIn("q35,accel=kvm,smm=off", arguments)
        self.assertIn(f"file={source_iso},if=none,format=raw,readonly=on,id=installcd", arguments)
        self.assertIn("usb-kbd,bus=xhci.0", arguments)
        self.assertIn("VGA", arguments)
        self.assertIn(
            f"file={self.root / 'build-config.img'},if=none,format=raw,readonly=on,id=configdisk",
            arguments,
        )
        self.assertIn(
            f"usb-storage,drive=configdisk,bus=xhci.0,removable=on,serial={_CONFIG_LABEL}",
            arguments,
        )
        self.assertIn(
            f"usb-storage,drive=resultdisk,bus=xhci.0,removable=on,serial={_BUILD_LABEL}",
            arguments,
        )
        self.assertIn("q35,accel=kvm,smm=off", arguments)
        self.assertEqual(
            arguments[:7],
            [str(self.fake_setpriv), "--reuid", "root", "--regid", "root", "--init-groups", "--"],
        )

    def test_fat_labels_are_valid_and_finalize_uses_build_label(self) -> None:
        self.assertLessEqual(len(_BUILD_LABEL), 11)
        self.assertLessEqual(len(_CONFIG_LABEL), 11)
        self.assertLessEqual(len(_RUN_LABEL), 11)
        finalize = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "resources"
            / "windows_kvm"
            / "base-finalize.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn(_BUILD_LABEL, finalize)
        self.assertNotIn("ORDIVON_BUILD", finalize)
        unattend = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "resources"
            / "windows_kvm"
            / "Autounattend.xml.in"
        ).read_text(encoding="utf-8")
        bootstrap = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "resources"
            / "windows_kvm"
            / "install-bootstrap.ps1"
        ).read_text(encoding="utf-8")
        setup_complete = (
            Path(__file__).parents[2]
            / "src"
            / "ordivon_security"
            / "resources"
            / "windows_kvm"
            / "SetupComplete.cmd"
        ).read_text(encoding="utf-8")
        self.assertIn(_CONFIG_LABEL, unattend)
        self.assertIn("install-bootstrap.ps1", unattend)
        self.assertIn(_CONFIG_LABEL, bootstrap)
        self.assertNotIn(_BUILD_LABEL, unattend)
        self.assertIn("BypassSecureBootCheck", unattend)
        self.assertNotIn("ChildCompletion", unattend)
        self.assertNotIn("/v setup.exe /t REG_DWORD /d 3 /f", unattend)
        self.assertNotIn("Select-Object -First 1", unattend)
        self.assertNotIn("-ErrorAction SilentlyContinue", unattend)
        self.assertNotIn("BypassTPMCheck", unattend)
        self.assertNotIn("BypassCPUCheck", unattend)
        self.assertNotIn("BypassRAMCheck", unattend)
        self.assertIn("SetupComplete.cmd", bootstrap)
        self.assertIn("p1-observer.ps1", bootstrap)
        self.assertIn(".ordivon-write-probe", finalize)
        self.assertIn("base-finalize-status.json", finalize)
        self.assertIn("Get-Volume -FileSystemLabel 'ORDIVONBLD' -ErrorAction Stop", finalize)
        self.assertLess(finalize.index(".ordivon-write-probe"), finalize.index("/active:no"))
        self.assertIn("base-finalize.log", setup_complete)
        self.assertIn("2>&1", setup_complete)

        import xml.etree.ElementTree as ET

        root = ET.fromstring(unattend.replace("@@PASSWORD@@", "test-password"))
        namespace = {"u": "urn:schemas-microsoft-com:unattend"}
        commands = root.findall(
            ".//u:settings[@pass='specialize']//u:RunSynchronousCommand",
            namespace,
        )
        self.assertEqual(len(commands), 1)
        command_path = commands[0].findtext("u:Path", namespaces=namespace)
        self.assertIsNotNone(command_path)
        assert command_path is not None
        self.assertLessEqual(len(command_path), 259)
        self.assertEqual(commands[0].findtext("u:Order", namespaces=namespace), "1")
        self.assertIn("Get-Volume -FileSystemLabel ORDIVONCFG", command_path)
        self.assertIn("install-bootstrap.ps1", command_path)

    def test_unattend_validation_rejects_oversized_deployment_path(self) -> None:
        oversized = "x" * 260
        unattend = """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>1</Order><Description>test</Description><Path>{oversized}</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>""".replace("{oversized}", oversized)
        with self.assertRaisesRegex(ValueError, r"Path exceeds 259 characters.*260"):
            _validate_unattend(unattend)

    def test_unattend_validation_does_not_echo_command_content(self) -> None:
        secret = "secret-command-material-" + "x" * 260
        unattend = """<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Deployment">
      <RunSynchronous>
        <RunSynchronousCommand wcm:action="add">
          <Order>7</Order><Description>test</Description><Path>{secret}</Path>
        </RunSynchronousCommand>
      </RunSynchronous>
    </component>
  </settings>
</unattend>""".replace("{secret}", secret)
        try:
            _validate_unattend(unattend)
        except ValueError as error:
            self.assertNotIn("secret-command-material", str(error))
            self.assertIn("order 7", str(error))
        else:
            self.fail("oversized unattend path was accepted")

    def test_fat_image_is_private_before_formatter_runs(self) -> None:
        source_iso = self.root / "private-source.iso"
        source_iso.write_bytes(b"iso")
        formatter = self.tools / "private-mkfs"
        formatter.write_text(
            '#!/bin/sh\ntest "$(stat -c %a "$3")" = 600\n',
            encoding="utf-8",
        )
        formatter.chmod(0o755)
        config = WindowsKvmBaseBuildConfig(
            state_root=self.root / "private-build-state",
            source_iso_path=source_iso,
            qemu_path=self.fake_qemu,
            qemu_img_path=self.fake_qemu_img,
            swtpm_path=self.fake_swtpm,
            setpriv_path=self.fake_setpriv,
            mkfs_fat_path=formatter,
            mcopy_path=self.fake_mcopy,
            firmware_code_path=self.firmware,
            firmware_vars_template_path=self.vars,
            run_user="root",
            run_group="root",
            memory_mib=512,
            vcpu_count=1,
            disk_size_gib=1,
        )
        image = self.root / "private-result.img"
        _create_fat_image(config, image, size_mib=1, label=_BUILD_LABEL)
        self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)

    def test_build_failure_removes_secret_state_and_writes_receipt(self) -> None:
        source_iso = self.root / "failure-source.iso"
        source_iso.write_bytes(b"synthetic-source")
        state_root = self.root / "failure-state"
        config = WindowsKvmBaseBuildConfig(
            state_root=state_root,
            source_iso_path=source_iso,
            qemu_path=self.fake_qemu,
            qemu_img_path=self.fake_qemu_img,
            swtpm_path=self.fake_swtpm,
            setpriv_path=self.fake_setpriv,
            mkfs_fat_path=self.fake_mkfs,
            mcopy_path=self.fake_mcopy,
            firmware_code_path=self.firmware,
            firmware_vars_template_path=self.vars,
            run_user="root",
            run_group="root",
            memory_mib=512,
            vcpu_count=1,
            disk_size_gib=1,
        )

        def fail_impl(*args: object, **kwargs: object) -> JsonObject:
            build_path = kwargs["build_path"]
            assert isinstance(build_path, Path)
            build_path.mkdir(mode=0o700)
            secret = build_path / "Autounattend.xml"
            secret.write_text("Temporary-Bootstrap-Password", encoding="utf-8")
            secret.chmod(0o600)
            raise RuntimeError("synthetic build failure")

        with (
            patch(
                "ordivon_security.evaluation.windows_kvm_build._build_windows_kvm_base_impl",
                side_effect=fail_impl,
            ),
            self.assertRaisesRegex(RuntimeError, "synthetic build failure"),
        ):
            build_windows_kvm_base(config)

        build_root = state_root / "build"
        self.assertEqual(list(build_root.iterdir()), [])
        receipts = list((state_root / "receipts").glob("windows-kvm-base-failure-*.json"))
        self.assertEqual(len(receipts), 1)
        raw = receipts[0].read_text(encoding="utf-8")
        receipt = json.loads(raw)
        self.assertIs(receipt["buildPathRemoved"], True)
        self.assertEqual(receipt["errorType"], "RuntimeError")
        self.assertEqual(receipt["errorMessage"], "synthetic build failure")
        self.assertNotIn("Temporary-Bootstrap-Password", raw)
        self.assertEqual(stat.S_IMODE(receipts[0].stat().st_mode), 0o600)

    def test_qmp_network_class_detection(self) -> None:
        no_network: JsonValue = [{"bus": 0, "devices": [{"class_info": {"class": 0x0106}}]}]
        with_network: JsonValue = [
            {
                "bus": 0,
                "devices": [
                    {"class_info": {"class": 0x0106}},
                    {"class_info": {"class": 0x0200, "desc": "Ethernet controller"}},
                ],
            }
        ]
        self.assertEqual(_pci_network_devices(no_network), [])
        self.assertEqual(len(_pci_network_devices(with_network)), 1)

    def test_provider_accepts_only_exact_benign_contract(self) -> None:
        backend = WindowsKvmEvaluationBackend(self.config)
        spec = self._spec(backend)
        backend._validate_spec(spec)

        wrong_action_authority = replace(
            spec.authority,
            permitted_actions=("execute-unknown-sample",),
            prohibited_actions=("network-access",),
        )
        wrong_action = replace(
            spec,
            authority=wrong_action_authority,
            requested_actions=("execute-unknown-sample",),
        )
        with self.assertRaisesRegex(ValueError, "admits only the benign fixture"):
            backend._validate_spec(wrong_action)

        network_authority = replace(spec.authority, allow_network=True)
        network_spec = replace(spec, authority=network_authority)
        with self.assertRaisesRegex(ValueError, "deny-all network"):
            backend._validate_spec(network_spec)

        wrong_media = replace(
            spec,
            sample=replace(spec.sample, media_type="application/octet-stream"),
        )
        with self.assertRaisesRegex(ValueError, "requires a PE executable"):
            backend._validate_spec(wrong_media)

        wrong_fixture = replace(
            spec,
            metadata={
                "fixtureId": "unknown",
                "fixtureCompilationDigest": "sha256:" + "4" * 64,
            },
        )
        with self.assertRaisesRegex(ValueError, "exact benign fixture"):
            backend._validate_spec(wrong_fixture)

        wrong_digest = "sha256:" + "5" * 64
        wrong_sample = SampleIdentity.create(
            sha256=wrong_digest,
            byte_length=spec.sample.byte_length,
            media_type=spec.sample.media_type,
            original_name=spec.sample.original_name,
        )
        wrong_bytes = replace(
            spec,
            sample=wrong_sample,
            authority=replace(spec.authority, sample_digest=wrong_digest),
        )
        with self.assertRaisesRegex(ValueError, "differs from the admitted benign fixture"):
            backend._validate_spec(wrong_bytes)

        wrong_attestation = replace(
            spec,
            metadata={
                "fixtureId": "ordivon-benign-v1",
                "fixtureCompilationDigest": "sha256:" + "6" * 64,
            },
        )
        with self.assertRaisesRegex(ValueError, "attestation differs"):
            backend._validate_spec(wrong_attestation)

        small_guardian = replace(spec.guardian_policy, max_processes=1)
        small_environment = replace(
            spec.environment,
            guardian_policy_digest=small_guardian.digest,
        )
        too_few_processes = replace(
            spec,
            guardian_policy=small_guardian,
            environment=small_environment,
        )
        with self.assertRaisesRegex(ValueError, "requires two admitted processes"):
            backend._validate_spec(too_few_processes)

    def test_terminate_pid_rejects_reused_process_identity(self) -> None:
        process = subprocess.Popen(["/usr/bin/sleep", "30"])
        try:
            start_time = _process_start_time(process.pid)
            self.assertIsNotNone(start_time)
            assert start_time is not None
            self.assertFalse(
                _terminate_pid(
                    process.pid,
                    expected_fragment="sleep",
                    expected_start_time=start_time + 1,
                )
            )
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_terminate_pid_treats_reaped_zombie_as_closed(self) -> None:
        process = subprocess.Popen(["/usr/bin/sleep", "30"])
        os.kill(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{process.pid}/stat").read_text(encoding="utf-8")
            except FileNotFoundError:
                break
            if state.rpartition(")")[2].strip().startswith("Z"):
                break
            time.sleep(0.01)
        start_time = _process_start_time(process.pid)
        self.assertIsNotNone(start_time)
        self.assertTrue(
            _terminate_pid(
                process.pid,
                expected_fragment="sleep",
                expected_start_time=start_time,
            )
        )
        self.assertFalse(Path(f"/proc/{process.pid}").exists())
        process.wait(timeout=5)

    def test_create_persists_recoverable_run_state(self) -> None:
        backend = WindowsKvmEvaluationBackend(self.config)
        spec = self._spec(backend)

        def create_overlay(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if arguments[0] == str(self.fake_qemu_img) and "create" in arguments:
                Path(arguments[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with (
            patch(
                "ordivon_security.providers.windows_kvm._run_checked",
                side_effect=create_overlay,
            ),
            patch(
                "ordivon_security.providers.windows_kvm.security_source_identity",
                return_value={
                    "componentId": "ordivon-security",
                    "revision": "git:test",
                    "revisionKind": "test",
                    "packageVersion": "test",
                },
            ),
        ):
            instance = backend.create("evaluation-run:ledger-test", spec)
        ledger_path = Path(str(instance.state["runStatePath"]))
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        self.assertEqual(ledger["phase"], "created")
        self.assertEqual(ledger["runId"], "evaluation-run:ledger-test")
        self.assertEqual(ledger["ownerPid"], os.getpid())
        self.assertIsInstance(ledger["ownerStartTime"], int)
        self.assertEqual(ledger["evaluationSpecDigest"], spec.digest)
        self.assertEqual(stat.S_IMODE(ledger_path.stat().st_mode), 0o600)
        self.assertTrue(backend.destroy(instance).clean)

    def test_destroy_removes_complete_run_directory_and_root_ledger(self) -> None:
        backend = WindowsKvmEvaluationBackend(self.config)
        run_path = self.root / "state" / "runs" / "destroy-test"
        run_path.mkdir(mode=0o700)
        overlay_path = run_path / "system-overlay.qcow2"
        overlay_path.write_bytes(b"overlay")
        ledger_path = backend.ledgers_root / "destroy-test.json"
        instance = EvaluationInstance(
            instance_id="evaluation-instance:destroy-test",
            generation="windows-kvm:test",
            state={
                "runPath": str(run_path),
                "runStatePath": str(ledger_path),
                "overlayPath": str(overlay_path),
                "varsPath": str(run_path / "OVMF_VARS.4m.fd"),
                "runDiskPath": str(run_path / "ordivon-run.img"),
                "qmpPath": str(run_path / "qmp.sock"),
                "tpmSocketPath": str(run_path / "swtpm.sock"),
                "tpmStatePath": str(run_path / "tpm-state"),
                "ownerPid": os.getpid(),
                "ownerStartTime": _process_start_time(os.getpid()),
                "security": {"componentId": "ordivon-security", "revision": "test"},
                "evaluationSpecDigest": "sha256:" + "7" * 64,
                "qemuPid": 0,
                "swtpmPid": 0,
                "staged": False,
                "qemuExited": False,
            },
        )
        backend._persist_run_state(instance, "created")
        receipt = backend.destroy(instance)
        self.assertTrue(receipt.clean)
        self.assertFalse(run_path.exists())
        self.assertFalse(ledger_path.exists())
        self.assertIs(receipt.details["ledgerRemoved"], True)
        self.assertEqual(receipt.details["residualObjects"], [])

    def test_destroy_without_persistent_ledger_cannot_claim_complete_closure(self) -> None:
        backend = WindowsKvmEvaluationBackend(self.config)
        run_path = self.root / "state" / "runs" / "legacy-destroy-test"
        run_path.mkdir(mode=0o700)
        instance = EvaluationInstance(
            instance_id="evaluation-instance:legacy-destroy-test",
            generation="windows-kvm:test",
            state={"runPath": str(run_path), "qemuPid": 0, "swtpmPid": 0},
        )
        receipt = backend.destroy(instance)
        self.assertFalse(receipt.clean)
        self.assertFalse(run_path.exists())
        self.assertIn("unknown-ledger", receipt.details["residualObjects"])

    def test_public_p0_acceptance_index_matches_implemented_scope(self) -> None:
        path = Path(__file__).parents[2] / "evidence" / "acceptance" / "windows-kvm-p0-5c6a854.json"
        index = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(index["kind"], "ordivon.security.windows-kvm-p0-acceptance")
        self.assertEqual(index["status"], "accepted-for-exact-benign-fixture-only")
        self.assertEqual(index["providerId"], WindowsKvmEvaluationBackend.provider_id)
        self.assertEqual(index["scope"]["permittedActions"], [_RUN_ACTION])
        self.assertEqual(index["scope"]["permittedFixtureIds"], ["ordivon-benign-v1"])
        self.assertIs(index["scope"]["unknownSampleExecution"], False)
        self.assertIs(index["scope"]["thirdPartySampleExecution"], False)
        self.assertIs(index["scope"]["generalPurposeSandbox"], False)
        self.assertTrue(all(value == "passed" for value in index["gates"].values()))
        self.assertIs(index["closeout"]["rawGuestStateRetained"], False)
        self.assertIs(index["closeout"]["sensitiveInstallationStateRetained"], False)

    def test_packaged_resources_are_present(self) -> None:
        resource_root = (
            Path(__file__).parents[2] / "src" / "ordivon_security" / "resources" / "windows_kvm"
        )
        expected = {
            "Autounattend.xml.in",
            "SetupComplete.cmd",
            "base-finalize.ps1",
            "benign_fixture.c",
            "fabric_canary.c",
            "topology_churn_canary.c",
            "readonly_media_fixture.c.in",
            "sacrificial_canary.c",
            "guest-runner.ps1",
            "install-bootstrap.ps1",
            "p1-observer.ps1",
            "p1_controller_canary.c",
            "p1_execution_control_canary.ps1",
            "p1_execution_control_launcher.c",
            "windows-host-caseb-baseline.ps1",
        }
        self.assertEqual({path.name for path in resource_root.iterdir()}, expected)
        for source_name in (
            "benign_fixture.c",
            "sacrificial_canary.c",
            "p1_controller_canary.c",
            "p1_execution_control_launcher.c",
        ):
            source = (resource_root / source_name).read_text(encoding="utf-8").lower()
            for token in ("ws2_32", "wininet", "winhttp", "urlmon", "socket(", "connect("):
                self.assertNotIn(token, source)
        policy_source = (resource_root / "p1_execution_control_canary.ps1").read_text(
            encoding="utf-8"
        ).lower()
        for token in ("invoke-webrequest", "webclient", "bitsadmin", "http://", "https://"):
            self.assertNotIn(token, policy_source)


if __name__ == "__main__":
    unittest.main()
