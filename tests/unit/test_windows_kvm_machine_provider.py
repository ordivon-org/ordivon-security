from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ordivon_security._canonical import JsonObject, canonical_digest
from ordivon_security.providers.windows_kvm import (
    WindowsKvmMachineConfig,
    WindowsKvmMachineProvider,
)


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


class _FakeQmpClient:
    def __init__(self, path: Path, *, timeout_seconds: int) -> None:
        self.path = path
        self.timeout_seconds = timeout_seconds

    def __enter__(self) -> _FakeQmpClient:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def execute(self, command: str, arguments: JsonObject | None = None):
        del arguments
        if command == "query-status":
            return {"status": "running"}
        if command == "query-pci":
            return [
                {"class_info": {"class": 0x0100}},
                {"class_info": {"class": 0x0200}, "qdev_id": "range-net0"},
            ]
        if command in {"quit", "system_powerdown"}:
            return {}
        raise AssertionError(f"unexpected QMP command: {command}")


class WindowsKvmMachineProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.root = Path(self.temporary.name)
        tools = self.root / "tools"
        tools.mkdir()
        self.qemu = self._tool(tools, "qemu-system-x86_64", "QEMU emulator version test")
        self.qemu_img = self._tool(tools, "qemu-img", "qemu-img version test")
        self.swtpm = self._tool(tools, "swtpm", "TPM emulator version test")
        self.setpriv = self._tool(tools, "setpriv", "setpriv test")
        self.firmware = self.root / "OVMF_CODE.fd"
        self.firmware.write_bytes(b"firmware")
        self.vars = self.root / "OVMF_VARS.fd"
        self.vars.write_bytes(b"vars")
        self.base_image = self.root / "base.qcow2"
        self.base_image.write_bytes(b"sealed-base-image")
        self.manifest = self.root / "base.manifest.json"
        environment_identity: JsonObject = {
            "sourceIsoDigest": "sha256:" + "1" * 64,
            "baseImageDigest": _digest(self.base_image),
            "baseVarsDigest": _digest(self.vars),
            "firmwareCodeDigest": _digest(self.firmware),
            "guestRunnerDigest": "sha256:" + "2" * 64,
            "windowsBuild": "10.0.test",
        }
        self.manifest.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "kind": "ordivon.security.windows-kvm-base-image",
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
                    "guest": {"windowsBuild": "10.0.test"},
                }
            ),
            encoding="utf-8",
        )
        self.config = WindowsKvmMachineConfig(
            state_root=self.root / "state",
            base_manifest_path=self.manifest,
            qemu_path=self.qemu,
            qemu_img_path=self.qemu_img,
            swtpm_path=self.swtpm,
            setpriv_path=self.setpriv,
            firmware_code_path=self.firmware,
            run_user="root",
            run_group="root",
            memory_mib=512,
            vcpu_count=1,
            qmp_ready_timeout_seconds=5,
            shutdown_grace_seconds=1,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _tool(root: Path, name: str, version: str) -> Path:
        path = root / name
        path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_identity_is_machine_only_and_contains_no_evaluation_admission(self) -> None:
        provider = WindowsKvmMachineProvider(self.config)
        identity = provider.execution_identity
        encoded = json.dumps(identity, sort_keys=True)
        self.assertEqual(identity["kind"], "ordivon.security.windows-kvm-machine-provider")
        self.assertEqual(identity["providerId"], "provider:windows-kvm")
        self.assertEqual(identity["implementationRevision"], "3")
        self.assertNotIn("admittedSampleDigest", encoded)
        self.assertNotIn("fixtureAttestationDigest", encoded)
        self.assertNotIn("admittedFixtureId", encoded)
        self.assertEqual(
            identity["configuration"]["networkAuthority"],
            "caller-supplied-qemu-topology",
        )

    def test_create_rejects_overlong_unix_socket_paths_before_run_creation(self) -> None:
        long_state_root = self.root / ("socket-path-" + "x" * 96)
        provider = WindowsKvmMachineProvider(
            replace(self.config, state_root=long_state_root)
        )
        token = "socket-limit-node"
        with self.assertRaisesRegex(ValueError, "Unix sockets require at most"):
            provider.create_state(
                token=token,
                instance_id="range-machine:socket-limit-node",
                generation="windows-kvm:test",
            )
        self.assertFalse((provider.runs_root / token).exists())

    def test_create_persist_and_destroy_are_independent_of_evaluation_spec(self) -> None:
        provider = WindowsKvmMachineProvider(self.config)

        def create_overlay(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if arguments[0] == str(self.qemu_img) and "create" in arguments:
                Path(arguments[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch(
            "ordivon_security.providers.windows_kvm._run_checked",
            side_effect=create_overlay,
        ):
            state = provider.create_state(
                token="war-node-01",
                instance_id="range-machine:war-node-01",
                generation="windows-kvm:test",
            )
        provider.persist_state(
            instance_id="range-machine:war-node-01",
            generation="windows-kvm:test",
            state=state,
            phase="created",
            extra={"rangeSessionId": "range-session:test"},
        )
        ledger = json.loads(Path(str(state["runStatePath"])).read_text(encoding="utf-8"))
        self.assertEqual(ledger["instanceId"], "range-machine:war-node-01")
        self.assertEqual(ledger["rangeSessionId"], "range-session:test")
        self.assertNotIn("evaluationSpecDigest", ledger)
        closure = provider.destroy_state(
            instance_id="range-machine:war-node-01",
            generation="windows-kvm:test",
            state=state,
            ledger_extra={"rangeSessionId": "range-session:test"},
        )
        self.assertTrue(closure.clean)
        self.assertEqual(closure.details["residualObjects"], [])
        self.assertFalse(Path(str(state["runPath"])).exists())
        self.assertFalse(Path(str(state["runStatePath"])).exists())

    def test_qmp_topology_is_external_machine_truth_not_guest_report(self) -> None:
        provider = WindowsKvmMachineProvider(self.config)
        state: JsonObject = {"qmpPath": str(self.root / "qmp.sock")}
        with patch("ordivon_security.providers.windows_kvm._QmpClient", _FakeQmpClient):
            topology = provider.inspect_qmp(state)
            provider.qmp_execute(state, "system_powerdown")
        self.assertIs(topology["networkDevicePresent"], True)
        self.assertEqual(len(topology["networkDevices"]), 1)
        self.assertIs(state["networkDevicePresent"], True)

    def test_qemu_spawn_and_exit_are_machine_provider_lifecycle_facts(self) -> None:
        provider = WindowsKvmMachineProvider(self.config)

        def create_overlay(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if arguments[0] == str(self.qemu_img) and "create" in arguments:
                Path(arguments[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch(
            "ordivon_security.providers.windows_kvm._run_checked",
            side_effect=create_overlay,
        ):
            state = provider.create_state(
                token="spawn-node-01",
                instance_id="range-machine:spawn-node-01",
                generation="windows-kvm:test",
            )

        class FakeProcess:
            pid = 4242
            returncode = 0

            def kill(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        process = FakeProcess()
        arguments = [
            str(self.setpriv),
            "--reuid",
            "root",
            "--regid",
            "root",
            "--init-groups",
            "--",
            str(self.qemu),
            "-name",
            "provider-owned-spawn",
        ]
        run_path = Path(str(state["runPath"]))
        with (
            patch(
                "ordivon_security.providers.windows_kvm.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "ordivon_security.providers.windows_kvm._process_start_time",
                return_value=777,
            ),
        ):
            returned = provider.start_qemu(
                instance_id="range-machine:spawn-node-01",
                generation="windows-kvm:test",
                state=state,
                arguments=arguments,
                stdout_path=run_path / "qemu.stdout.log",
                stderr_path=run_path / "qemu.stderr.log",
                ledger_extra={"rangeSessionId": "range-session:test"},
            )
        self.assertIs(returned, process)
        self.assertEqual(state["qemuPid"], 4242)
        self.assertEqual(state["qemuStartTime"], 777)
        ledger_path = Path(str(state["runStatePath"]))
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        self.assertEqual(ledger["phase"], "executing")
        self.assertEqual(ledger["qemuPid"], 4242)
        self.assertEqual(ledger["qemuStartTime"], 777)

        provider.record_qemu_exit(
            instance_id="range-machine:spawn-node-01",
            generation="windows-kvm:test",
            state=state,
            exit_code=0,
            ledger_extra={"rangeSessionId": "range-session:test"},
        )
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        self.assertEqual(ledger["phase"], "executed")
        self.assertIs(ledger["qemuExited"], True)
        self.assertEqual(ledger["qemuExitCode"], 0)
        self.assertTrue(
            provider.destroy_state(
                instance_id="range-machine:spawn-node-01",
                generation="windows-kvm:test",
                state=state,
                ledger_extra={"rangeSessionId": "range-session:test"},
            ).clean
        )

    def test_qemu_spawn_can_bind_an_existing_network_namespace(self) -> None:
        provider = WindowsKvmMachineProvider(self.config)

        def create_overlay(arguments: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if arguments[0] == str(self.qemu_img) and "create" in arguments:
                Path(arguments[-1]).write_bytes(b"overlay")
            return subprocess.CompletedProcess(arguments, 0, "", "")

        with patch(
            "ordivon_security.providers.windows_kvm._run_checked",
            side_effect=create_overlay,
        ):
            state = provider.create_state(
                token="netns-node-01",
                instance_id="range-machine:netns-node-01",
                generation="windows-kvm:test",
            )

        class FakeProcess:
            pid = 4343

            def kill(self) -> None:
                return None

            def wait(self, timeout: float | None = None) -> int:
                del timeout
                return 0

        ip_path = self._tool(self.root, "ip", "ip test")
        arguments = [
            str(self.setpriv),
            "--reuid",
            "root",
            "--regid",
            "root",
            "--init-groups",
            "--",
            str(self.qemu),
            "-name",
            "provider-netns-spawn",
        ]
        run_path = Path(str(state["runPath"]))
        with (
            patch(
                "ordivon_security.providers.windows_kvm.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "s5fabric (id: 1)\n", ""),
            ),
            patch(
                "ordivon_security.providers.windows_kvm.subprocess.Popen",
                return_value=FakeProcess(),
            ) as popen,
            patch(
                "ordivon_security.providers.windows_kvm._process_start_time",
                return_value=888,
            ),
        ):
            provider.start_qemu(
                instance_id="range-machine:netns-node-01",
                generation="windows-kvm:test",
                state=state,
                arguments=arguments,
                stdout_path=run_path / "qemu.stdout.log",
                stderr_path=run_path / "qemu.stderr.log",
                ledger_extra={"rangeSessionId": "range-session:test"},
                network_namespace="s5fabric",
                ip_path=ip_path,
            )
        self.assertEqual(
            popen.call_args.args[0],
            [str(ip_path), "netns", "exec", "s5fabric", *arguments],
        )
        self.assertEqual(state["networkNamespace"], "s5fabric")
        ledger = json.loads(Path(str(state["runStatePath"])).read_text(encoding="utf-8"))
        self.assertEqual(ledger["networkNamespace"], "s5fabric")

    def test_qemu_spawn_rejects_command_outside_provider_identity(self) -> None:
        provider = WindowsKvmMachineProvider(self.config)
        with self.assertRaisesRegex(ValueError, "execution identity"):
            provider.start_qemu(
                instance_id="range-machine:invalid",
                generation="windows-kvm:test",
                state={},
                arguments=[str(self.qemu)],
                stdout_path=self.root / "qemu.stdout.log",
                stderr_path=self.root / "qemu.stderr.log",
            )


class QmpEventWaitTests(unittest.TestCase):
    def test_event_wait_uses_one_deadline_read_and_does_not_retry_timed_out_reader(self) -> None:
        from ordivon_security.providers.windows_kvm import _QmpClient

        class FakeSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def settimeout(self, value: float) -> None:
                self.timeouts.append(value)

        client = _QmpClient(Path("/tmp/unused-qmp.sock"), timeout_seconds=5)
        socket = FakeSocket()
        client._socket = socket  # type: ignore[assignment]
        with (
            patch.object(
                client, "_read_message", side_effect=TimeoutError("simulated timeout")
            ) as read,
            self.assertRaisesRegex(TimeoutError, "QMP event did not arrive: RESET"),
        ):
            client.wait_for_event("RESET", timeout_seconds=30)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(len(socket.timeouts), 1)
        self.assertGreater(socket.timeouts[0], 29)


if __name__ == "__main__":
    unittest.main()
