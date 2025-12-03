control 'SV-244534' do
  title 'RHEL 8 must configure the use of the pam_faillock.so module in the
/etc/pam.d/password-auth file.'
  desc 'By limiting the number of failed logon attempts, the risk of
unauthorized system access via user password guessing, otherwise known as
brute-force attacks, is reduced. Limits are imposed by locking the account.

    In RHEL 8.2 the "/etc/security/faillock.conf" file was incorporated to
centralize the configuration of the pam_faillock.so module.  Also introduced is
a "local_users_only" option that will only track failed user authentication
attempts for local users in /etc/passwd and ignore centralized (AD, IdM, LDAP,
etc.) users to allow the centralized platform to solely manage user lockout.

    From "faillock.conf" man pages: Note that the default directory that
"pam_faillock" uses is usually cleared on system boot so the access will be
reenabled after system reboot. If that is undesirable a different tally
directory must be set with the "dir" option.
    The preauth argument must be used when the module is called before the
modules which ask for the user credentials such as the password.'
  desc 'check', %q(Note: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the pam_faillock.so module is present and is listed before the pam.unix.so line in the "/etc/pam.d/password-auth" file:
Note: The first field in the output is the line number of the entry

$ sudo grep -E -n 'pam_faillock.so|pam_unix.so' /etc/pam.d/password-auth

7:auth required pam_faillock.so preauth silent
11:auth sufficient pam_unix.so
15:auth required pam_faillock.so authfail
19:account required pam_faillock.so
20:account required pam_unix.so
31:password sufficient pam_unix.so sha512 shadow use_authtok
40:session required pam_unix.so

If the pam_faillock.so module is not present in the "/etc/pam.d/password-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.)
  desc 'fix', 'Configure the operating system to include the use of the pam_faillock.so
module in the /etc/pam.d/password-auth file.

    Add/Modify the appropriate sections of the "/etc/pam.d/password-auth"
file to match the following lines:
    Note: The "preauth" line must be listed before pam_unix.so.

    auth required pam_faillock.so preauth
    auth required pam_faillock.so authfail
    account required pam_faillock.so'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-244534'
  tag rid: 'SV-244534r1069319_rule'
  tag stig_id: 'RHEL-08-020026'
  tag fix_id: 'F-47766r743850_fix'
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

  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
    its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
    its('lines') { should match_pam_rule('account required pam_faillock.so') }
  end
end
