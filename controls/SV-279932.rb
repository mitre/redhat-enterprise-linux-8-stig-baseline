control 'SV-279932' do
  title 'RHEL 8 cryptographic policy must not be overridden.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', 'Verify RHEL 8 cryptographic policies are not overridden.

Verify the configured policy matches the generated policy with the following command:

$ sudo update-crypto-policies --is-applied

The configured policy is applied

If the returned message does not match the above, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to correctly implement the systemwide cryptographic policies by reinstalling the crypto-policies package contents.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-84492r1156347_chk'
  tag severity: 'high'
  tag gid: 'V-279932'
  tag rid: 'SV-279932r1156349_rule'
  tag stig_id: 'RHEL-08-010270'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-84397r1156348_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers or crypto policy is waived', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) && !input('crypto_policy_waived')
  }

  crypto_policies_dir = '/etc/crypto-policies/back-ends'
  expected_link_path_dir = '/usr/share/crypto-policies/FIPS'

  crypto_policies = command("ls -l #{crypto_policies_dir} | awk '{ print $9 }'").stdout.strip.split("\n")

  failing_crypto_policies = {}

  crypto_policies.each do |crypto_policy|
    service = "#{crypto_policies_dir}/#{crypto_policy}"
    link_path = file(service).link_path

    if link_path.nil?
      failing_crypto_policies[service] = 'No link path found'
    elsif !link_path.match?(/^#{expected_link_path_dir}/)
      failing_crypto_policies[service] = link_path
    end
  end

  describe 'Crypto policies' do
    it 'should link to the correct libriries' do
      expect(failing_crypto_policies).to be_empty, "Failing crypto policies:\n\t- #{failing_crypto_policies}"
    end
  end

  output = command('update-crypto-policies --check 2>&1 && echo PASS').stdout.strip
  last_line = output.lines.map(&:strip).reject(&:empty?).last.to_s

  describe 'System cryptographic policy must match the generated policy' do
    subject { last_line }
    it { should cmp 'PASS' }
  end
end
