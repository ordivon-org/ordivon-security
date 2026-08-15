#!/usr/bin/env python3
"""Deterministic TS9 displacement assessment over current Security source.

This does not install or execute another hypervisor manager. It measures the current
mechanical/semantic split and records explicit triggers that could justify a future
Packer/libvirt treatment.
"""
from __future__ import annotations
import json, shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FILES=[
 'src/ordivon_security/providers/windows_kvm.py',
 'src/ordivon_security/evaluation/windows_kvm.py',
 'src/ordivon_security/evaluation/windows_kvm_build.py',
 'src/ordivon_security/evaluation/windows_kvm_reconcile.py',
 'src/ordivon_security/range/windows_fabric.py',
 'src/ordivon_security/range/windows_fabric_reconcile.py',
]

def metrics():
 out={}
 for rel in FILES:
  text=(ROOT/rel).read_text()
  out[rel]={
   'lines':len(text.splitlines()),
   'qemuMentions':text.lower().count('qemu'),
   'qmpMentions':text.lower().count('qmp'),
   'ledgerMentions':text.lower().count('ledger'),
   'swtpmMentions':text.lower().count('swtpm'),
  }
 return out

def assessment():
 m=metrics()
 return {
  'schemaVersion':1,
  'kind':'ordivon.security-virtualization-displacement-assessment',
  'phase':'TS9',
  'installed':{
   'qemu-system-x86_64':bool(shutil.which('qemu-system-x86_64')),
   'qemu-img':bool(shutil.which('qemu-img')),
   'swtpm':bool(shutil.which('swtpm')),
   'virsh':bool(shutil.which('virsh')),
   'virt-install':bool(shutil.which('virt-install')),
   'packer':bool(shutil.which('packer')),
  },
  'currentSourceMetrics':m,
  'responsibilityMatrix':[
   {'responsibility':'VM create/start/stop generic mechanics','currentOwner':'WindowsKvmMachineProvider','libvirt':'strong-mechanical-match','packer':'not-runtime-owner','securityMustRemainOwner':['admission identity','exact run ledger','residual-closure claim']},
   {'responsibility':'QMP topology/event evidence','currentOwner':'WindowsKvmMachineProvider','libvirt':'query-pass-through-possible-but-not-semantic-replacement','packer':'no','securityMustRemainOwner':['which QMP facts count as evidence','event/currentness interpretation']},
   {'responsibility':'QEMU/swtpm PID+start-time orphan recovery','currentOwner':'WindowsKvmMachineProvider','libvirt':'different-daemon/domain-lifecycle model','packer':'no','securityMustRemainOwner':['controller-death continuity','exact orphan identity','fresh-controller reconciliation']},
   {'responsibility':'disposable overlay/UEFI/TPM build mechanics','currentOwner':'Security build/provider','libvirt':'partial','packer':'strong-build-match','securityMustRemainOwner':['sealed-base digest','no-NIC policy','run/case binding','post-build verification']},
   {'responsibility':'unattended Windows base image construction','currentOwner':'windows_kvm_build.py','libvirt':'not-image-builder','packer':'strong-build-match','securityMustRemainOwner':['base manifest authority','guest observer/controller sealing','acceptance evidence']},
   {'responsibility':'isolated Range fabric/topology churn','currentOwner':'Security Range','libvirt':'network abstraction would add a second state model','packer':'no','securityMustRemainOwner':['actor authority','topology truth','packet evidence','relation recovery']},
   {'responsibility':'stopped-overlay out-of-band truth','currentOwner':'Security observer path','libvirt':'no semantic replacement','packer':'no','securityMustRemainOwner':['filesystem fact interpretation','case/evidence attribution']},
  ],
  'disposition':{
   'libvirt':{
    'decision':'defer-no-acquisition',
    'reason':'Generic lifecycle overlap is real, but current high-value mechanics are exact QMP/process/ledger/recovery evidence. Introducing libvirt now adds daemon/domain/XML state without deleting Security-owned consequence semantics.',
    'reconsiderWhen':['a second VM family repeats generic lifecycle code','Security needs persistent multi-domain inventory/migration','QEMU argv/process mechanics become a measured recurring defect source'],
   },
   'packer':{
    'decision':'retain-challenger-no-acquisition',
    'reason':'Packer matches the Windows base-image construction responsibility much more closely than runtime Range execution. It may replace boot/install/image plumbing while Security retains sealed-base/evidence authority.',
    'reconsiderWhen':['the Windows base is rebuilt for a new observer/controller generation','base-image build changes become frequent','current build plumbing causes a reproducible maintenance failure'],
   },
  },
  'migrationAuthorized':False,
  'packageInstallationAuthorized':False,
  'boundary':'This assessment can rank displacement candidates but cannot replace Security evidence/authority or authorize package installation.',
 }

def main(): print(json.dumps(assessment(),indent=2,sort_keys=True))
if __name__=='__main__': main()
