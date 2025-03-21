control 'SV-230338' do
  title 'RHEL 8 must ensure account lockouts persist.'
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
  desc 'check', 'Check that the faillock directory contents persists after a reboot with the
following commands:

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

    If the "dir" option is not set to a non-default documented tally log
directory on the "preauth" and "authfail" lines with the
"pam_faillock.so" module, or is missing from these lines, this is a finding.

    $ sudo grep pam_faillock.so /etc/pam.d/system-auth

    auth required pam_faillock.so preauth dir=/var/log/faillock silent audit
deny=3 even_deny_root fail_interval=900 unlock_time=0
    auth required pam_faillock.so authfail dir=/var/log/faillock unlock_time=0
    account required pam_faillock.so

    If the "dir" option is not set to a non-default documented tally log
directory on the "preauth" and "authfail" lines with the
"pam_faillock.so" module, or is missing from these lines, this is a finding.'
  desc 'fix', 'Configure the operating system maintain the contents of the faillock
directory after a reboot.

    Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" and
"/etc/pam.d/password-auth" files to match the following lines:

    Note: Using the default faillock directory of /var/run/faillock will result
in the contents being cleared in the event of a reboot.

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
  tag gid: 'V-230338'
  tag rid: 'SV-230338r1017150_rule'
  tag stig_id: 'RHEL-08-020016'
  tag fix_id: 'F-32982r567761_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  message = <<~MESSAGE
    \n\nThis check only applies to RHEL versions 8.0 or 8.1.\n
    The system is running RHEL version: #{os.version}, this requirement is Not Applicable.
  MESSAGE
  only_if(message, impact: 0.0) do
    os.version.minor.between?(0, 1)
  end

  pam_auth_files = input('pam_auth_files')

  describe pam(pam_auth_files['password-auth']) do
    its('lines') {
      should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_args("dir=#{input('log_directory')}")
    }
  end
  describe pam(pam_auth_files['system-auth']) do
    its('lines') {
      should match_pam_rule('auth [default=die]|required pam_faillock.so').all_with_args("dir=#{input('log_directory')}")
    }
  end
end
