control 'SV-272484' do
  title 'RHEL 8 must elevate the SELinux context when an administrator calls the sudo command.'
  desc 'Preventing nonprivileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Nonprivileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from nonprivileged users.'
  desc 'check', 'Verify the operating system elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be run as root:

# grep -r sysadm_r /etc/sudoers /etc/sudoers.d
/etc/sudoers.d/admins:<username> ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If conflicting results are returned, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.'
  desc 'fix', 'Configure the operating system to elevate the SELinux context when an administrator calls the sudo command.

Edit a file in the "/etc/sudoers.d" directory with the following command:

$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:

{designated_group_or_user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

Remove any configurations that conflict with the above from the following locations:

/etc/sudoers
/etc/sudoers.d/'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag gid: 'V-272484'
  tag rid: 'SV-272484r1134875_rule'
  tag stig_id: 'RHEL-08-010455'
  tag fix_id: 'F-76444r1134874_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  # The actual STIG check is "grep -r sysadm_r /etc/sudoers /etc/sudoers.d". A compliant
  # system must contain at least one sudo rule that elevates the SELinux type and role to
  # "sysadm_t"/"sysadm_r", and must not contain any conflicting "sysadm_r" entries (i.e. any
  # line referencing sysadm_r that does not properly elevate both TYPE=sysadm_t and
  # ROLE=sysadm_r).
  sysadm_r_lines = command('grep -rh sysadm_r /etc/sudoers /etc/sudoers.d 2>/dev/null')
                   .stdout.lines
                   .map(&:strip)
                   .reject { |l| l.empty? || l.start_with?('#') }

  # A well-formed elevation rule sets both TYPE=sysadm_t and ROLE=sysadm_r.
  elevating_rules = sysadm_r_lines.select do |l|
    l.match?(/\bTYPE=sysadm_t\b/) && l.match?(/\bROLE=sysadm_r\b/)
  end

  # Any line mentioning sysadm_r that is not a well-formed elevation rule is a conflict.
  conflicting_rules = sysadm_r_lines - elevating_rules

  describe 'A designated sudoers administrator rule elevating the SELinux context to sysadm_t/sysadm_r' do
    it 'should be configured' do
      expect(elevating_rules).not_to be_empty, 'No sudoers rule found that elevates the SELinux type and role to "sysadm_t"/"sysadm_r"'
    end
  end

  describe 'Conflicting "sysadm_r" sudoers configurations' do
    it 'should not be present' do
      expect(conflicting_rules).to be_empty, "Conflicting sysadm_r configurations found:\n\t- #{conflicting_rules.join("\n\t- ")}"
    end
  end
end
