control 'SV-230332' do
  title 'RHEL 8 must automatically lock an account when three unsuccessful
logon attempts occur.'
  desc 'By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    RHEL 8 can utilize the "pam_faillock.so" for this purpose. Note that
manual changes to the listed files may be overwritten by the "authselect"
program.

    From "Pam_Faillock" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.'
  desc 'check', 'Check that the system locks an account after three unsuccessful logon
attempts with the following commands:

    Note: If the System Administrator demonstrates the use of an approved
centralized account management method that locks an account after three
unsuccessful logon attempts within a period of 15 minutes, this requirement is
not applicable.

    Note: This check applies to RHEL versions 8.0 and 8.1, if the system is
RHEL version 8.2 or newer, this check is not applicable.

    $ sudo grep pam_faillock.so /etc/pam.d/password-auth

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    If the "deny" option is not set to "3" or less (but not "0") on the
"preauth" line with the "pam_faillock.so" module, or is missing from this
line, this is a finding.

    If any line referencing the "pam_faillock.so" module is commented out,
this is a finding.

    $ sudo grep pam_faillock.so /etc/pam.d/system-auth

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    If the "deny" option is not set to "3" or less (but not "0") on the
"preauth" line with the "pam_faillock.so" module, or is missing from this
line, this is a finding.

    If any line referencing the "pam_faillock.so" module is commented out,
this is a finding.'
  desc 'fix', 'Configure the operating system to lock an account when three unsuccessful
logon attempts occur.

    Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" and
"/etc/pam.d/password-auth" files to match the following lines:

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    The "sssd" service must be restarted for the changes to take effect. To
restart the "sssd" service, run the following command:

    $ sudo systemctl restart sssd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-230332'
  tag rid: 'SV-230332r1017144_rule'
  tag stig_id: 'RHEL-08-020010'
  tag fix_id: 'F-32976r567743_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  unsuccessful_attempts = input('unsuccessful_attempts')
  pam_auth_files = input('pam_auth_files')

  only_if('This system uses Centralized Account Management to manage this requirement', impact: 0.0) {
    !input('central_account_management')
  }

  message = <<~MESSAGE
    \n\nThis check only applies to RHEL versions 8.0 or 8.1.\n
    The system is running RHEL version: #{os.version}, this requirement is Not Applicable.
  MESSAGE
  if os.version.minor >= 2
    impact 0.0
    describe 'This requirement only applies to RHEL 8 version(s) 8.0 and 8.1' do
      skip message
    end
  else
    [
      pam_auth_files['password-auth'],
      pam_auth_files['system-auth']
    ].each do |path|
      describe pam(path) do
        its('lines') {
          should match_pam_rule('auth [default=die]|required pam_faillock.so preauth').all_with_integer_arg('deny',
                                                                                                            '<=', unsuccessful_attempts)
        }
        its('lines') {
          should match_pam_rule('auth [default=die]|required pam_faillock.so preauth').all_with_integer_arg('deny',
                                                                                                            '>=', 0)
        }
      end
    end
  end
end
