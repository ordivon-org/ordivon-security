from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ordivon_security.providers.windows_kvm import WindowsKvmMachineClosure, WindowsKvmMachineConfig
from ordivon_security.range import RangeSessionSpec
from ordivon_security.range.windows_sacrificial import (
    AdversarialWindowsRange,
    SacrificialWindowsRangeConfig,
)


class _FakeProcess:
    def __init__(self) -> None:
        self.pid = 4242
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 143

    def kill(self) -> None:
        self.returncode = 137


class _FakeMachineProvider:
    provider_id = "provider:windows-kvm"

    def __init__(self, config: WindowsKvmMachineConfig, *, network_present: bool = False) -> None:
        self.config = config
        self.base = SimpleNamespace(
            environment_image_digest="sha256:" + "a" * 64,
            base_image_path=config.state_root / "base.qcow2",
        )
        self.network_present = network_present
        self.process = _FakeProcess()
        self.destroy_called = False
        self.exit_codes: list[int] = []
        self.persisted_phases: list[str] = []

    @property
    def execution_identity(self):
        return {"providerId": self.provider_id, "implementationRevision": "test"}

    def create_state(self, *, token: str, instance_id: str, generation: str):
        run_path = self.config.state_root / "runs" / token
        run_path.mkdir(parents=True)
        tpm_state = run_path / "tpm-state"
        tpm_state.mkdir()
        return {
            "runPath": str(run_path),
            "runStatePath": str(self.config.state_root / "run-ledgers" / f"{token}.json"),
            "overlayPath": str(run_path / "system-overlay.qcow2"),
            "varsPath": str(run_path / "OVMF_VARS.4m.fd"),
            "qmpPath": str(run_path / "qmp.sock"),
            "tpmSocketPath": str(run_path / "swtpm.sock"),
            "tpmStatePath": str(tpm_state),
            "qemuPid": 0,
            "swtpmPid": 0,
            "instanceId": instance_id,
            "generation": generation,
        }

    def persist_state(self, *, phase: str, **_: object) -> None:
        self.persisted_phases.append(phase)

    def start_swtpm(self, **_: object) -> int:
        return 3131

    def start_qemu(self, **_: object) -> _FakeProcess:
        return self.process

    def inspect_qmp(self, state):
        state["networkDevicePresent"] = self.network_present
        return {
            "status": {"status": "running"},
            "pci": [],
            "networkDevices": ([{"class_info": {"class": 0x0200}}] if self.network_present else []),
            "networkDevicePresent": self.network_present,
        }

    def wait_for_qmp_event(self, state, event_name: str, *, timeout_seconds: int):
        del state, timeout_seconds
        return {"event": event_name, "data": {"reason": "guest-reset"}}

    def record_qemu_exit(self, *, exit_code: int, **_: object) -> None:
        self.exit_codes.append(exit_code)

    def qmp_execute(self, state, command: str, *, timeout_seconds: int = 5):
        del state, timeout_seconds
        if command == "quit":
            self.process.returncode = 0
        return {}

    def destroy_state(self, **_: object) -> WindowsKvmMachineClosure:
        self.destroy_called = True
        return WindowsKvmMachineClosure(
            clean=True,
            details={"residualObjects": [], "runDirectoryRemoved": True, "ledgerRemoved": True},
        )


class SacrificialWindowsRangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        tool_paths = {}
        for name in ("qemu", "qemu-img", "swtpm", "setpriv", "mkfs.fat", "mcopy"):
            path = self.tools / name
            exit_code = 1 if name == "mcopy" else 0
            path.write_text(f"#!/bin/sh\nexit {exit_code}\n", encoding="utf-8")
            path.chmod(0o755)
            tool_paths[name] = path
        self.firmware = self.root / "OVMF_CODE.fd"
        self.firmware.write_bytes(b"firmware")
        self.manifest = self.root / "base.manifest.json"
        self.manifest.write_text("{}", encoding="utf-8")
        self.canary = self.root / "s3-canary.exe"
        self.canary.write_bytes(b"owned-s3-canary")
        import hashlib

        self.canary_digest = "sha256:" + hashlib.sha256(self.canary.read_bytes()).hexdigest()
        self.machine = WindowsKvmMachineConfig(
            state_root=self.root / "state",
            base_manifest_path=self.manifest,
            qemu_path=tool_paths["qemu"],
            qemu_img_path=tool_paths["qemu-img"],
            swtpm_path=tool_paths["swtpm"],
            setpriv_path=tool_paths["setpriv"],
            firmware_code_path=self.firmware,
            run_user="root",
            run_group="root",
            memory_mib=512,
            vcpu_count=1,
            qmp_ready_timeout_seconds=5,
            shutdown_grace_seconds=1,
        )
        self.range_config = SacrificialWindowsRangeConfig(
            machine=self.machine,
            canary_path=self.canary,
            canary_digest=self.canary_digest,
            mkfs_fat_path=tool_paths["mkfs.fat"],
            mcopy_path=tool_paths["mcopy"],
            run_disk_mib=1,
            max_runtime_seconds=30,
        )
        self.spec = RangeSessionSpec(
            session_id="range-session:s3-test",
            revision="1",
            range_id="range:windows-sacrificial-s3",
            actor_ids=(),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _fake_media_command(arguments: list[str], **_: object) -> None:
        del arguments

    def _build_backend(self, provider: _FakeMachineProvider) -> AdversarialWindowsRange:
        with patch(
            "ordivon_security.range.windows_sacrificial.WindowsKvmMachineProvider",
            return_value=provider,
        ):
            backend = AdversarialWindowsRange(self.range_config)
        return backend

    def test_create_confirms_external_containment_and_observes_guest_reset(self) -> None:
        provider = _FakeMachineProvider(self.machine)
        backend = self._build_backend(provider)
        with (
            patch(
                "ordivon_security.range.windows_sacrificial._run_checked",
                side_effect=self._fake_media_command,
            ),
            patch("ordivon_security.range.windows_sacrificial._set_owner"),
        ):
            instance = backend.create(self.spec)
        run = backend._run(instance)
        assert run.watcher is not None
        run.watcher.join(timeout=1)
        events = backend.events(instance, after_cursor=-1)
        event_types = [event.event_type for event in events]
        self.assertIn("machine.containment-confirmed", event_types)
        self.assertIn("machine.reset-observed", event_types)
        reset_event = next(
            event for event in events if event.event_type == "machine.reset-observed"
        )
        self.assertEqual(reset_event.plane, "management")
        self.assertTrue(run.reset_observed)
        self.assertFalse(run.state["networkDevicePresent"])
        receipt = backend.destroy(instance)
        self.assertTrue(receipt["clean"])
        self.assertTrue(provider.destroy_called)

    def test_network_device_fails_closed_and_cleans_partial_machine(self) -> None:
        provider = _FakeMachineProvider(self.machine, network_present=True)
        backend = self._build_backend(provider)
        with (
            patch(
                "ordivon_security.range.windows_sacrificial._run_checked",
                side_effect=self._fake_media_command,
            ),
            patch("ordivon_security.range.windows_sacrificial._set_owner"),
            self.assertRaisesRegex(RuntimeError, "network device"),
        ):
            backend.create(self.spec)
        self.assertTrue(provider.destroy_called)
        self.assertEqual(backend._runs, {})

    def test_guest_canary_result_is_recorded_as_claim_not_world_truth(self) -> None:
        provider = _FakeMachineProvider(self.machine)
        backend = self._build_backend(provider)
        with (
            patch(
                "ordivon_security.range.windows_sacrificial._run_checked",
                side_effect=self._fake_media_command,
            ),
            patch("ordivon_security.range.windows_sacrificial._set_owner"),
        ):
            instance = backend.create(self.spec)
        run = backend._run(instance)
        assert run.watcher is not None
        run.watcher.join(timeout=1)
        provider.process.returncode = 0
        guest_claim = {
            "schemaVersion": 1,
            "kind": "ordivon.security.s3-sacrificial-canary-result",
            "fixtureId": "ordivon-s3-sacrificial-canary-v1",
            "observerKilled": True,
            "guestRunnerKilled": True,
            "persistenceFiredAfterReboot": True,
            "syntheticGuestLogDeleted": True,
            "rebootContinuationObserved": True,
            "networkRequested": False,
            "completed": True,
        }

        def extract(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            destination = Path(arguments[-1])
            destination.write_text(json.dumps(guest_claim), encoding="utf-8")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch(
            "ordivon_security.range.windows_sacrificial.subprocess.run",
            side_effect=extract,
        ):
            inspected = backend.inspect(instance)
            events = backend.events(instance, after_cursor=-1)
        self.assertEqual(inspected["guestCanaryClaim"], guest_claim)
        claim_event = next(
            event for event in events if event.event_type == "guest.sacrificial-canary-claim"
        )
        self.assertEqual(claim_event.payload["authority"], "guest-claim-not-world-truth")
        self.assertEqual(provider.exit_codes, [0])
        backend.destroy(instance)

    def test_execution_identity_binds_security_source_revision(self) -> None:
        provider = _FakeMachineProvider(self.machine)
        backend = self._build_backend(provider)
        identity = backend.execution_identity
        security_source = identity["securitySource"]
        self.assertIsInstance(security_source, dict)
        self.assertEqual(security_source["componentId"], "ordivon-security")
        self.assertIn("revision", security_source)

    def test_s4_offline_disk_truth_is_emitted_separately_from_guest_claim(self) -> None:
        provider = _FakeMachineProvider(self.machine)
        backend = self._build_backend(provider)
        with (
            patch(
                "ordivon_security.range.windows_sacrificial._run_checked",
                side_effect=self._fake_media_command,
            ),
            patch("ordivon_security.range.windows_sacrificial._set_owner"),
        ):
            instance = backend.create(self.spec)
        run = backend._run(instance)
        assert run.watcher is not None
        run.watcher.join(timeout=1)
        provider.process.returncode = 0
        run.guest_claim_recorded = True

        persisted_exe = "/ProgramData/Ordivon/S3/s3-canary.exe"
        scheduled_task = "/Windows/System32/Tasks/OrdivonS3CanaryPersistence"
        persistence_marker = "/ProgramData/Ordivon/S3/persistence-fired.marker"
        deletion_marker = "/ProgramData/Ordivon/S3/synthetic-log-deleted.marker"
        synthetic_log = "/ProgramData/Ordivon/S3/synthetic-guest.log"
        outer = self

        class FakeInspector:
            def __init__(self) -> None:
                self.calls = 0

            def inspect(self, image_path, *, file_paths, text_checks):
                del image_path, file_paths, text_checks
                self.calls += 1
                if self.calls == 1:
                    return {
                        "files": [
                            {"path": persisted_exe, "present": False},
                            {"path": scheduled_task, "present": False},
                            {"path": persistence_marker, "present": False},
                            {"path": deletion_marker, "present": False},
                            {"path": synthetic_log, "present": False},
                        ],
                        "textChecks": {
                            "scheduledTaskCommandIsPersistedCanary": False,
                            "scheduledTaskArgumentsPersisted": False,
                        },
                    }
                return {
                    "files": [
                        {"path": persisted_exe, "present": True, "digest": outer.canary_digest},
                        {"path": scheduled_task, "present": True},
                        {
                            "path": persistence_marker,
                            "present": True,
                            "digest": (
                                "sha256:ec6372af8577f375d4fa5cfffe9e4f513244c9e9df4985cfb7e24350836963a3"
                            ),
                        },
                        {
                            "path": deletion_marker,
                            "present": True,
                            "digest": (
                                "sha256:d2b5be46eadffc18fdbc4f849d4ded8e69c99379b23923b907d06acf9e173e8e"
                            ),
                        },
                        {"path": synthetic_log, "present": False},
                    ],
                    "textChecks": {
                        "scheduledTaskCommandIsPersistedCanary": True,
                        "scheduledTaskArgumentsPersisted": True,
                    },
                }

        truth = backend.capture_offline_disk_truth(instance, FakeInspector())  # type: ignore[arg-type]
        self.assertTrue(all(truth["facts"].values()))
        events = backend.events(instance, after_cursor=-1)
        truth_event = next(
            event for event in events if event.event_type == "world.disk-state-observed"
        )
        self.assertEqual(truth_event.plane, "world-truth")
        self.assertEqual(truth_event.payload["authority"], "host-offline-read-only-ntfs")
        backend.destroy(instance)

    def test_s4_offline_disk_truth_rejects_live_machine(self) -> None:
        provider = _FakeMachineProvider(self.machine)
        backend = self._build_backend(provider)
        with (
            patch(
                "ordivon_security.range.windows_sacrificial._run_checked",
                side_effect=self._fake_media_command,
            ),
            patch("ordivon_security.range.windows_sacrificial._set_owner"),
        ):
            instance = backend.create(self.spec)
        with self.assertRaisesRegex(RuntimeError, "machine to be stopped"):
            backend.capture_offline_disk_truth(instance, SimpleNamespace())  # type: ignore[arg-type]
        backend.destroy(instance)

    def test_checkpoint_is_deliberately_absent_in_s3(self) -> None:
        provider = _FakeMachineProvider(self.machine)
        backend = self._build_backend(provider)
        with self.assertRaisesRegex(NotImplementedError, "does not implement checkpoints"):
            backend.checkpoint(
                SimpleNamespace(instance_id="range-instance:none", session_id="range-session:none"),
                "before",
            )


if __name__ == "__main__":
    unittest.main()
