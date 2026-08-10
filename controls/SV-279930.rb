control 'SV-279930' do
  title 'RHEL 8 IP tunnels must use FIPS 140-3-approved cryptographic algorithms.'
  desc 'Overriding the system crypto policy makes the behavior of the Libreswan service violate expectations and makes system configuration more fragmented.'
  desc 'check', 'Note: If the IPsec service is not installed, this is not applicable.

Verify the IPsec service uses the system crypto policy with the following command:

$ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf

/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config
/etc/ipsec.conf:include /etc/ipsec.d/*.conf

If the ipsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.'
  desc 'fix', 'Configure Libreswan to use the system cryptographic policy.

Add the following line to "/etc/ipsec.conf":

include /etc/crypto-policies/back-ends/libreswan.config'
  impact 0.7
  tag check_id: 'C-84490r1184238_chk'
  tag severity: 'high'
  tag gid: 'V-279930'
  tag rid: 'SV-279930r1184239_rule'
  tag stig_id: 'RHEL-08-010280'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-84395r1156342_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  expected_value = input('approved_crypto_backend')

  setting_check = command('grep include /etc/ipsec.conf /etc/ipsec.d/*.conf').stdout.strip.match?(/^.*:?[^#]include\s*#{expected_value}$/)

  describe 'RHEL 8 IPsec config' do
    it "should include the conf file '#{expected_value}'" do
      expect(setting_check).to eq(true), "Conf file '#{expected_value}' not included in ipsec config"
    end
  end
end
