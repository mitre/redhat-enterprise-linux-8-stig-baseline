control 'SV-272482' do
  title 'The RHEL 8 SSH client must be configured to use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.'
  desc 'check', 'Verify the RHEL 8 SSH client is configured to use only MACs employing FIPS 140-3-approved algorithms.

To verify the MACs in the systemwide SSH configuration file, use the following command:

$ grep -i MACs /etc/crypto-policies/back-ends/openssh.config

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If the MACs entries in the "openssh.config" file have any hashes other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-2562", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 SSH client to use only MACs employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-272482'
  tag rid: 'SV-272482r1184242_rule'
  tag stig_id: 'RHEL-08-010296'
  tag fix_id: 'F-76442r1155366_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('use_fips') == false
    impact 0.0
    describe 'This control is Not Applicable as FIPS is not required for this system' do
      skip 'This control is Not Applicable as FIPS is not required for this system'
    end
  else
    # Define the required MACs
    required_macs = input('openssh_client_required_macs')

    crypto_policy_file = '/etc/crypto-policies/back-ends/openssh.config'

    # The SSH client crypto policy file uses bare ssh_config(5) directives
    # (e.g. "MACs hmac-sha2-512-etm@openssh.com,..."), not the CRYPTO_POLICY
    # variable format used by the SSH server (opensshserver.config) file.
    config = file(crypto_policy_file)

    describe config do
      it { should exist }
    end

    if config.exist?
      # Grab the active (uncommented) MACs directive, case-insensitive, and
      # split its comma-delimited value into the list of configured MACs.
      macs_line = config.content.lines.grep(/^\s*MACs\s+/i).last
      configured_macs = macs_line.nil? ? [] : macs_line.sub(/^\s*MACs\s+/i, '').strip.split(',')

      # The MACs directive must be present and contain exactly the required
      # algorithms. V2R7 removed the requirement that the algorithms appear in
      # a specific order; only the set must match.
      describe "The MACs option in the crypto policy file #{crypto_policy_file}" do
        it 'is present and contains exactly the required algorithms' do
          expect(macs_line).not_to be_nil, "The crypto policy file #{crypto_policy_file} \ndoes not contain an active MACs directive\n\n\texpected: #{required_macs}"
          expect(configured_macs).to match_array(required_macs), "The MACs option in the crypto policy file does not contain exactly the required algorithms:\n\n\texpected (any order): #{required_macs}\n\tgot: #{configured_macs}"
        end
      end
    end
  end
end
