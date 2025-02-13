control 'SV-268322' do
  title 'RHEL 8 must not allow blank or null passwords in the system-auth file.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.'
  desc 'check', 'To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/system-auth

If output is produced, this is a finding.'
  desc 'fix', 'Remove any instances of the "nullok" option in the "/etc/pam.d/system-auth" file to prevent logons with empty passwords.

Note: Manual changes to the listed file may be overwritten by the "authselect" program.'
  impact 0.7
  tag check_id: 'C-72343r1017566_chk'
  tag severity: 'high'
  tag gid: 'V-268322'
  tag rid: 'SV-268322r1017568_rule'
  tag stig_id: 'RHEL-08-020331'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-72246r1017567_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  describe command ("grep -i nullok /etc/pam.d/system-auth") do
    its("stdout") {should eq ""}
end
