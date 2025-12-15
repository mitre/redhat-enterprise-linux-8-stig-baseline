control 'SV-251716' do
  title 'RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. This is set in both:
/etc/pam.d/password-auth
/etc/pam.d/system-auth
By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Note: This requirement applies to RHEL versions 8.4 or newer. If the system is RHEL below version 8.4, this requirement is not applicable.

Verify RHEL 8 is configured to limit the "pwquality" retry option to "3".

Check for the use of the retry option in the security directory with the following command:

$ grep -w retry /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf

retry = 3

If the value of "retry" is set to "0" or greater than "3", or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to limit the "pwquality" retry option to "3".

Add or update the following line in the "/etc/security/pwquality.conf" file or a file in the "/etc/security/pwquality.conf.d/" directory to contain the "retry" parameter:

retry = 3'
  impact 0.5
  tag check_id: 'C-55153r1069267_chk'
  tag severity: 'medium'
  tag gid: 'V-251716'
  tag rid: 'SV-251716r1069329_rule'
  tag stig_id: 'RHEL-08-020104'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55107r1069268_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  only_if('This requirement only applies to RHEL 8 versions 8.4 or above', impact: 0.0) {
    os.version.minor >= 4
  }

  describe 'System pwquality setting' do
    subject { parse_config(command('grep -rh retry /etc/security/pwquality.conf*').stdout.strip) }
    its('retry') { should cmp >= input('min_retry') }
  end
end
