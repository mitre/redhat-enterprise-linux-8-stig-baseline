control 'SV-274877' do
  title 'RHEL 8 must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user, must have the permissions set to 755 or more restrictive, and have no extended rights that allow a nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify RHEL 8 is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands do not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
auditctl -w /etc/cron.d/ -p wa -k cronjobs
auditctl -w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78978r1106147_chk'
  tag severity: 'medium'
  tag gid: 'V-274877'
  tag rid: 'SV-274877r1106148_rule'
  tag stig_id: 'RHEL-08-030655'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-78883r1101908_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
