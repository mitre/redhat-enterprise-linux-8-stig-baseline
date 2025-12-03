control 'SV-230252' do
  title 'The RHEL 8 operating system must implement DOD-approved encryption to protect the confidentiality of SSH server connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH connection.'
  desc 'check', 'Verify the SSH server is configured to use only ciphers employing FIPS 140-3 approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ sudo grep -i ciphers /etc/crypto-policies/back-ends/opensshserver.config
-oCiphers=aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr

If the ciphers entries in the "opensshserver.config" file have any hashes other than "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr", the order differs from the example above, or they are missing or commented out, this is a finding.'
  desc 'fix', %q(Configure the RHEL 8 SSH server to use only ciphers employing FIPS 140-3 approved algorithms by updating the "/etc/crypto-policies/back-ends/opensshserver.config" file with the following commands.

To manually update the ciphers in the systemwide SSH configuration, use the following command:

$ sudo sed -i -E 's/(-oCiphers=)[^ ]*/\1aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr/' "$(readlink -f /etc/crypto-policies/back-ends/opensshserver.config)"

A reboot is required for the changes to take effect.)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00065']
  tag gid: 'V-230252'
  tag rid: 'SV-230252r1067104_rule'
  tag stig_id: 'RHEL-08-010291'
  tag fix_id: 'F-32896r1044816_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?)
  }

  required_ciphers = input('openssh_client_required_ciphers')

  describe parse_config_file('/etc/crypto-policies/back-ends/opensshserver.config') do
    its('CRYPTO_POLICY') { should_not be_nil }
  end

  crypto_policy = parse_config_file('/etc/crypto-policies/back-ends/opensshserver.config')['CRYPTO_POLICY']

  unless crypto_policy.nil?
    describe parse_config(crypto_policy.gsub(/\s|'/, "\n")) do
      # -oCiphers is a single line of comma-delineated cipher values
      its('-oCiphers') { should cmp required_ciphers.join(',') }
    end
  end
end
