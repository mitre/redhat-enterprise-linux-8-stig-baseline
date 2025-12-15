control 'SV-272483' do
  title 'RHEL 8 SSH client must be configured to use only ciphers employing FIPS 140-3 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/opensshserver.config file.

The system will attempt to use the first hash presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest hash available to secure the SSH connection.

'
  desc 'check', 'Verify the SSH client is configured to use only ciphers employing FIPS 140-3 approved algorithms.

To verify the Ciphers in the systemwide SSH configuration file, use the following command:

$ sudo grep -i ciphers /etc/crypto-policies/back-ends/openssh.config
-oCiphers=aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr

If the ciphers entries in the "openssh.config" file have any hashes other than "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr", or they are missing, or commented out, this is a finding.'
  desc 'fix', %q(Configure the RHEL 8 SSH client to use only ciphers employing FIPS 140-3 approved algorithms by updating the "/etc/crypto-policies/back-ends/openssh.config" file with the following commands.

To manually update the ciphers in the systemwide SSH configuration, use the following command:

$ sudo sed -i -E 's/(-oCiphers=)[^ ]*/\1aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr/' "$(readlink -f /etc/crypto-policies/back-ends/openssh.config)"

A reboot is required for the changes to take effect.)
  impact 0.5
  tag check_id: 'C-76537r1069409_chk'
  tag severity: 'medium'
  tag gid: 'V-272483'
  tag rid: 'SV-272483r1069415_rule'
  tag stig_id: 'RHEL-08-010297'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-76443r1069336_fix'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000125-GPOS-00066']
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
