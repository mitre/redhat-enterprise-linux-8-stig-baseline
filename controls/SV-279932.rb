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
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag gid: 'V-279932'
  tag rid: 'SV-279932r1156349_rule'
  tag stig_id: 'RHEL-08-010270'
  tag fix_id: 'F-84397r1156348_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # "update-crypto-policies --is-applied" reports whether the configured
  # systemwide crypto policy matches the generated back-end configuration.
  # When the policy has not been overridden, it returns
  # "The configured policy is applied".
  describe command('update-crypto-policies --is-applied') do
    its('stdout.strip') { should cmp 'The configured policy is applied' }
  end
end
