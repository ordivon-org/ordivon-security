import unittest
from scripts.assess_virtualization_displacement import assessment

class VirtualizationDisplacementTests(unittest.TestCase):
    def test_ts9_displacement_keeps_security_authority_and_does_not_authorize_install(self):
        value=assessment()
        self.assertFalse(value['migrationAuthorized'])
        self.assertFalse(value['packageInstallationAuthorized'])
        self.assertEqual(value['disposition']['libvirt']['decision'],'defer-no-acquisition')
        self.assertEqual(value['disposition']['packer']['decision'],'retain-challenger-no-acquisition')
        by={row['responsibility']:row for row in value['responsibilityMatrix']}
        self.assertIn('exact run ledger',by['VM create/start/stop generic mechanics']['securityMustRemainOwner'])
        self.assertIn('QMP',by['QMP topology/event evidence']['responsibility'])

    def test_ts9_metrics_are_bound_to_real_current_security_sources(self):
        value=assessment(); metrics=value['currentSourceMetrics']
        provider=metrics['src/ordivon_security/providers/windows_kvm.py']
        build=metrics['src/ordivon_security/evaluation/windows_kvm_build.py']
        self.assertGreater(provider['lines'],500); self.assertGreater(provider['qmpMentions'],20); self.assertGreater(provider['ledgerMentions'],20)
        self.assertGreater(build['lines'],500); self.assertGreater(build['qemuMentions'],10)

if __name__=='__main__': unittest.main()
