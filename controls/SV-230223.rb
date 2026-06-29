control 'SV-230223' do
  title 'RHEL 8 must implement a FIPS 140-3-compliant systemwide cryptographic policy.'
  desc 'Centralized cryptographic policies simplify applying secure ciphers across an operating system and the applications that run on that operating system. Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data.'
  desc 'check', %q(Verify RHEL 8 is set to use a FIPS 140-3-compliant systemwide cryptographic policy with the following command:

$ sudo update-crypto-policies --show

FIPS:STIG

If the systemwide crypto policy is not set to "FIPS", this is a finding.

Note: If subpolicies have been configured, they could be listed in a colon-separated list starting with "FIPS" as follows FIPS:<SUBPOLICY-NAME>. This is not a finding.

Note: Subpolicies like AD-SUPPORT must be configured according to the latest guidance from the operating system vendor.

Verify the current minimum crypto-policy configuration with the following commands:

$ sudo grep -E 'rsa_size|hash' /etc/crypto-policies/state/CURRENT.pol

hash = SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512
min_rsa_size = 2048

If the "hash" values do not include at least the following FIPS 140-3-compliant algorithms "SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512", this is a finding.

If there are algorithms that include "SHA1" or a hash value less than "224" this is a finding.

If the "min_rsa_size" is not set to a value of at least "2048", this is a finding.

If these commands do not return any output, this is a finding.)
  desc 'fix', 'Configure RHEL 8 to use a FIPS 140-3-compliant systemwide cryptographic policy.

Create a subpolicy for enhancements to the base systemwide crypto-policy by creating the file /etc/crypto-policies/policies/modules/STIG.pmod with the following content:

# Define ciphers and MACs for OpenSSH and libssh
cipher@SSH=AES-256-GCM AES-256-CTR AES-128-GCM AES-128-CTR
mac@SSH=HMAC-SHA2-512 HMAC-SHA2-256

Apply the policy enhancements to the FIPS systemwide cryptographic policy level with the following command:

$ sudo update-crypto-policies --set FIPS:STIG

Note: If additional subpolicies are being employed, they must be added to the update-crypto-policies command.

To make the cryptographic settings effective for already running services and applications, restart the system:

$ sudo reboot'
  impact 0.7
  tag check_id: 'C-32892r1155354_chk'
  tag severity: 'high'
  tag gid: 'V-230223'
  tag rid: 'SV-230223r1155356_rule'
  tag stig_id: 'RHEL-08-010020'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-32867r1155355_fix'
  tag satisfies: ['SRG-OS-000396-GPOS-00176', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-002890', 'CCI-003123', 'CCI-000068']
  tag nist: ['SC-13 b', 'MA-4 (6)', 'AC-17 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe command('update-crypto-policies --show') do
    its('stdout') { should match(/FIPS/) }
  end

  describe parse_config_file('/etc/crypto-policies/state/CURRENT.pol') do
    its(['min_rsa_size']) { should cmp >= 2048 }
    its(['hash']) {
      should include 'SHA2-256', 'SHA2-384', 'SHA2-512', 'SHA2-224',
                     'SHA3-256', 'SHA3-384', 'SHA3-512', 'SHAKE-256'
    }
    its(['hash']) { should_not match(/SHA-?1\b/i) }
    its(['hash']) {
      is_expected.to satisfy('no hash size < 256 (except 224)') { |s|
                       sizes = s.scan(/-(\d+)/).flatten.map(&:to_i)
                       (sizes - [224]).all? { |n| n >= 256 }
                     }
    }
  end
end
