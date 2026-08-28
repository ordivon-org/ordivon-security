from __future__ import annotations

import argparse
import unittest
from pathlib import Path
from unittest.mock import patch

from ordivon_security.windows_kvm_recovery_acceptance_support import (
    ledger_semantic_binding,
    process_truth,
    windows_kvm_machine_config,
)


class WindowsKvmRecoveryAcceptanceSupportTests(unittest.TestCase):
    def test_ledger_semantic_binding_keeps_exact_actor_request(self) -> None:
        binding = {"effectId": "range-effect:test", "authorityId": "range-authority:test"}
        ledger = {"actorReplacementRequest": binding}
        self.assertIs(ledger_semantic_binding(ledger), binding)
        self.assertIsNone(ledger_semantic_binding({}))

    @patch("ordivon_security.windows_kvm_recovery_acceptance_support.WindowsKvmMachineConfig")
    def test_machine_config_preserves_physical_acceptance_defaults(self, config_type) -> None:
        args = argparse.Namespace(
            state_root=Path("/tmp/security-state"),
            base_manifest=Path("/tmp/base.json"),
            memory_mib=3072,
            vcpus=3,
        )
        sentinel = object()
        config_type.return_value = sentinel
        self.assertIs(windows_kvm_machine_config(args), sentinel)
        config_type.assert_called_once_with(
            state_root=Path("/tmp/security-state"),
            base_manifest_path=Path("/tmp/base.json"),
            qemu_path=Path("/usr/bin/qemu-system-x86_64"),
            qemu_img_path=Path("/usr/bin/qemu-img"),
            swtpm_path=Path("/usr/bin/swtpm"),
            setpriv_path=Path("/usr/bin/setpriv"),
            firmware_code_path=Path("/usr/share/edk2/x64/OVMF_CODE.4m.fd"),
            run_user="qemu",
            run_group="qemu",
            memory_mib=3072,
            vcpu_count=3,
            qmp_ready_timeout_seconds=60,
            shutdown_grace_seconds=15,
        )

    @patch("ordivon_security.windows_kvm_recovery_acceptance_support._identity_alive")
    def test_process_truth_preserves_identity_observation_roles(self, alive) -> None:
        alive.side_effect = [False, True, True, True, False]
        truth = process_truth(
            {
                "ownerPid": 1,
                "ownerStartTime": 10,
                "qemuPid": 2,
                "qemuStartTime": 20,
                "swtpmPid": 3,
                "swtpmStartTime": 30,
                "capturePid": 4,
                "captureStartTime": 40,
                "peerPid": 5,
                "peerStartTime": 50,
            }
        )
        self.assertEqual(
            truth,
            {
                "ownerAlive": False,
                "qemuAlive": True,
                "swtpmAlive": True,
                "captureAlive": True,
                "peerAlive": False,
            },
        )


if __name__ == "__main__":
    unittest.main()
