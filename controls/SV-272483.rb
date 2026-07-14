control 'SV-272483' do
  title 'The RHEL 8 SSH client must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.

'
  desc 'check', 'Verify the RHEL 8 SSH client is configured to use only ciphers employing FIPS 140-3-approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ grep -i Ciphers /etc/crypto-policies/back-ends/openssh.config

Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "openssh.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 SSH client to use only ciphers employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00066']
  tag gid: 'V-272483'
  tag rid: 'SV-272483r1184243_rule'
  tag stig_id: 'RHEL-08-010297'
  tag fix_id: 'F-76443r1155360_fix'
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
    required_ciphers = input('openssh_client_required_ciphers')

    crypto_policy_file = '/etc/crypto-policies/back-ends/openssh.config'

    # The client back-end file uses standard ssh_config syntax: a space-separated
    # "Ciphers a,b,c" directive (unlike the server back-end's CRYPTO_POLICY='-oCiphers=...' form).
    ciphers_line = file(crypto_policy_file).content.to_s.lines.map(&:strip).find do |line|
      line =~ /^Ciphers\s+/i
    end

    configured_ciphers = ciphers_line.nil? ? nil : ciphers_line.sub(/^Ciphers\s+/i, '').split(',').map(&:strip)

    describe "The crypto policy file #{crypto_policy_file}" do
      it 'contains an active (uncommented) Ciphers entry' do
        expect(ciphers_line).not_to be_nil, "The Ciphers entry in #{crypto_policy_file} is missing or commented out."
      end
    end

    unless configured_ciphers.nil?
      # V2R7 requires exactly the approved set of ciphers; no other ciphers may be present.
      describe 'The Ciphers entry in the crypto policy file' do
        it 'contains exactly the required ciphers' do
          expect(configured_ciphers).to match_array(required_ciphers), "The Ciphers entry in #{crypto_policy_file} does not contain exactly the required ciphers:\n\n\texpected (any order): #{required_ciphers}\n\tgot: #{configured_ciphers}"
        end
      end
    end
  end
end
