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
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000396-GPOS-00176', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000478-GPOS-00223', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag gid: 'V-230223'
  tag rid: 'SV-230223r1155356_rule'
  tag stig_id: 'RHEL-08-010020'
  tag fix_id: 'F-32867r1155355_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable in a container' do
      skip 'The host OS controls the FIPS mode settings. The host OS should also be scanned with the applicable OS validation profile.'
    end
  elsif input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    # The systemwide crypto policy must be set to FIPS (optionally with a
    # colon-separated subpolicy list, e.g. "FIPS:STIG").
    describe command('update-crypto-policies --show') do
      its('stdout.strip') { should match(/^FIPS(:\S+)?$/) }
    end

    # The required FIPS 140-3-compliant hash algorithms that must be present in
    # the "hash" value of the current crypto policy.
    required_hashes = %w[SHA2-256 SHA2-384 SHA2-512 SHA2-224 SHA3-256 SHA3-384 SHA3-512]
    min_rsa_size = 2048

    current_pol = file('/etc/crypto-policies/state/CURRENT.pol')

    describe current_pol do
      it { should exist }
    end

    if current_pol.exist?
      pol = parse_config(current_pol.content.to_s)

      hash_value = pol.params['hash'].to_s
      configured_hashes = hash_value.split(/\s+/).reject(&:empty?)

      describe 'The systemwide crypto-policy "hash" configuration' do
        it 'must include all required FIPS 140-3-compliant hash algorithms' do
          missing = required_hashes - configured_hashes
          expect(missing).to be_empty, "Missing required hash algorithm(s): #{missing.join(', ')}\n\tgot: #{hash_value}"
        end

        it 'must not include any SHA1 algorithm' do
          sha1 = configured_hashes.select { |h| h =~ /SHA1/i }
          expect(sha1).to be_empty, "Disallowed SHA1 algorithm(s) present: #{sha1.join(', ')}"
        end

        it 'must not include any hash value with a length less than 224' do
          weak = configured_hashes.select { |h| (m = h[/(\d+)\s*$/, 1]) && m.to_i < 224 }
          expect(weak).to be_empty, "Disallowed hash value(s) less than 224: #{weak.join(', ')}"
        end
      end

      rsa_value = pol.params['min_rsa_size'].to_s.strip

      describe 'The systemwide crypto-policy "min_rsa_size" configuration' do
        it 'must be set to a value of at least 2048' do
          expect(rsa_value).not_to be_empty, 'min_rsa_size is not configured in /etc/crypto-policies/state/CURRENT.pol'
          expect(rsa_value.to_i).to be >= min_rsa_size, "Expected min_rsa_size >= #{min_rsa_size}, got: #{rsa_value}"
        end
      end
    end
  end
end
