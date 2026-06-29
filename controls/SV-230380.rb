control 'SV-230380' do
  title 'RHEL 8 must not allow accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', %q(To verify that null passwords cannot be used, run the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permitemptypasswords'

/etc/ssh/sshd_config:PermitEmptyPasswords no

If "PermitEmptyPasswords" is set to "yes", this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Edit the following line in "etc/ssh/sshd_config" to prevent logons with empty passwords.

PermitEmptyPasswords no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-33049r1069225_chk'
  tag severity: 'high'
  tag gid: 'V-230380'
  tag rid: 'SV-230380r1069308_rule'
  tag stig_id: 'RHEL-08-020330'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33024r743992_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-004066']
  tag nist: ['CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'
  tag 'container-conditional'

  users_with_blank_passwords = shadow.where { password.nil? || password.empty? }.users - input('users_allowed_blank_passwords')

  describe 'All users' do
    it 'should have a password set' do
      fail_msg = "Users with blank passwords:\n\t- #{users_with_blank_passwords.join("\n\t- ")}"
      expect(users_with_blank_passwords).to be_empty, fail_msg
    end
  end
end
