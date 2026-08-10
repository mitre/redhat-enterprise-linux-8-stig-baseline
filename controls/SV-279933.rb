control 'SV-279933' do
  title 'RHEL 8 must have the crypto-policies package installed.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', 'Verify the RHEL 8 crypto-policies package is installed with the following command:

$ sudo dnf list --installed crypto-policies

Updating Subscription Management repositories.
Installed Packages
crypto-policies.noarch                     20230731-1.git3177e06.el8                      @rhel-8-for-x86_64-baseos-rpms

If the crypto-policies package is not installed, this is a finding.'
  desc 'fix', 'Install the crypto-policies package (if the package is not already installed) with the following command:

$ sudo dnf -y install crypto-policies'
  impact 0.7
  tag check_id: 'C-84493r1156350_chk'
  tag severity: 'high'
  tag gid: 'V-279933'
  tag rid: 'SV-279933r1156352_rule'
  tag stig_id: 'RHEL-08-010015'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-84398r1156351_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package('crypto-policies') do
    it { should be_installed }
  end
end
