control 'SV-272483' do
  title 'The RHEL 8 SSH client must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography, enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.'
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
  tag check_id: 'C-76537r1155359_chk'
  tag severity: 'high'
  tag gid: 'V-272483'
  tag rid: 'SV-272483r1184243_rule'
  tag stig_id: 'RHEL-08-010297'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-76443r1155360_fix'
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-000068', 'CCI-000877', 'CCI-002890', 'CCI-003123', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'MA-4 c', 'MA-4 (6)', 'SC-8']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  approved_ciphers = input('approved_openssh_client_conf')['ciphers']

  describe file('/etc/crypto-policies/back-ends/openssh.config') do
    it { should exist }
  end

  options = { assignment_regex: /^(\S+)\s+(.+)$/ }
  openssh_conf = parse_config_file('/etc/crypto-policies/back-ends/openssh.config', options).params.to_h { |k, v| [k.downcase, v.to_s.split(',').map(&:strip)] }
  actual_ciphers = openssh_conf['ciphers'] || []

  describe 'OpenSSH client configuration' do
    it 'implements approved encryption ciphers' do
      expect(actual_ciphers).to eq(approved_ciphers), "OpenSSH client cipher configuration actual value:\n\t#{actual_ciphers.inspect}\ndoes not match the expected value:\n\t#{approved_ciphers.inspect}"
    end
  end
end
