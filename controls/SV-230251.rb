control 'SV-230251' do
  title 'The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.'
  desc 'check', 'Verify the RHEL 8 SSH server is configured to use only MACs employing FIPS 140-3-approved algorithms.

To verify the MACs in the systemwide SSH configuration file, use the following command:

$ sudo grep -i MACs /etc/crypto-policies/back-ends/opensshserver.config

-oMACs=hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If the MACs entries in the "opensshserver.config" file have any hashes other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure the RHEL 8 SSH server to use only MACs employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-230251'
  tag rid: 'SV-230251r1184240_rule'
  tag stig_id: 'RHEL-08-010290'
  tag fix_id: 'F-32895r1155369_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

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
    # Define the required algorithms
    required_algorithms = input('openssh_server_required_algorithms')

    # TODO: make a simple resource for this based off 'login_defs' or 'yum' as a model

    # Parse the configuration file to get the value of "CRYPTO_POLICY"
    crypto_policy = parse_config_file('/etc/crypto-policies/back-ends/opensshserver.config')['CRYPTO_POLICY']

    # Parse the CRYPTO_POLICY string into a hash of configuration options
    config_options = crypto_policy.scan(/-o(\w+)=([\w\-,@]+.)/).to_h

    # Split each configuration option's values into an array
    config_options.transform_values! { |v| v.split(',') }

    # Define the path to the crypto policy file
    crypto_policy_file = '/etc/crypto-policies/back-ends/opensshserver.config'

    # Test that the crypto policy file is configured with the required algorithms
    describe "The crypto policy file #{crypto_policy_file}" do
      it 'is configured with the required algorithms' do
        expect(crypto_policy).not_to be_nil, "The crypto policy file #{crypto_policy_file} \ndoes not contain the required algorithms\n\n\t#{required_algorithms}."
      end
    end

    # Test that the MACS option in the crypto policy file contains exactly the required algorithms
    # (V2R7 removed the requirement that the algorithms appear in a specific order; only the set must match)
    describe 'The MACs option in the crypto policy file' do
      it 'contains the required algorithms' do
        expect(config_options['MACS']).to match_array(required_algorithms), "The MACS option in the crypto policy file does not contain exactly the required algorithms:\n\n\texpected (any order): #{required_algorithms}\n\tgot:#{config_options['MACS']}"
      end
    end
  end
end
