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
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-279933'
  tag rid: 'SV-279933r1156352_rule'
  tag stig_id: 'RHEL-08-010015'
  tag fix_id: 'F-84398r1156351_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
  tag 'host'
  tag 'container'

  describe package('crypto-policies') do
    it { should be_installed }
  end
end
