control 'SV-272482' do
  title 'RHEL 8 SSH client must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organizationally controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8.4 and newer releases incorporate system-wide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the /etc/sysconfig/sshd file. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/openssh.config file.'
  desc 'check', 'Verify the SSH client is configured to use only MACs employing FIPS 140-3 approved algorithms with the following command:

$ grep -i macs /etc/crypto-policies/back-ends/openssh.config

-oMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If the MACs entries in the "openssh.config" file have any hashes other than "MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512", they are missing, or commented out, this is a finding.'
  desc 'fix', %q(Configure the RHEL 8 SSH client to use only MACs employing FIPS 140-3 approved algorithms.

For RHEL 8.4 and newer, update the "/etc/crypto-policies/back-ends/openssh.config" file with the following command:
sudo sed -i -E 's/(-oMACs=)[^ ]*/\1hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256/' "$(readlink -f /etc/crypto-policies/back-ends/openssh.config)"

A reboot is required for the changes to take effect.)
  impact 0.5
  tag check_id: 'C-76536r1069412_chk'
  tag severity: 'medium'
  tag gid: 'V-272482'
  tag rid: 'SV-272482r1069414_rule'
  tag stig_id: 'RHEL-08-010296'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-76442r1069413_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
