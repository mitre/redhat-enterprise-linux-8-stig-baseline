control 'SV-230318' do
  title 'All RHEL 8 world-writable directories must be owned by root, sys, bin,
or an application user.'
  desc 'If a world-writable directory is not owned by root, sys, bin, or an
application User Identifier (UID), unauthorized users may be able to modify
files created by others.

    The only authorized public directories are those temporary directories
supplied with the system or those designed to be temporary file repositories.
The setting is normally reserved for directories used by the system and by
users for temporary file storage, (e.g., /tmp), and for directories requiring
global read/write access.'
  desc 'check', 'Verify RHEL 8 world writable directories are owned by root, a system account, or an application account with the following command:

$ sudo find / -xdev -type d -perm -0002 -uid +999 -exec stat -c "%U, %u, %A, %n" {} \\; 2>/dev/null

If there is output that indicates world-writable directories are owned by any account other than root or an approved system account, this is a finding.'
  desc 'fix', 'Configure all RHEL 8 public directories to be owned by root or a system account to prevent unauthorized and unintended information transferred via shared system resources.

Use the following command template to set ownership of public directories to root or a system account:

$ sudo chown [root or system account] [Public Directory]'
  impact 0.0
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230318'
  tag rid: 'SV-230318r1155352_rule'
  tag stig_id: 'RHEL-08-010700'
  tag fix_id: 'F-32962r1155351_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if input('disable_slow_controls')
    describe 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute.' do
      skip 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute. You must enable this control for a full accredidation for production.'
    end
  else

    partitions = etc_fstab.params.map { |partition| partition['mount_point'] }.uniq

    cmd = "find #{partitions.join(' ')} -xdev -type d -perm -0002 -uid +999 -exec stat -c '%U, %u, %A, %n' {} \\; 2>/dev/null"
    world_writable_dirs = command(cmd).stdout.strip

    describe 'World-writable directories owned by an account with a UID greater than 999' do
      skip "This control must be reviewed manually.\n\nPer DISA RHEL 8 STIG V2R7 (RHEL-08-010700), world-writable directories may be owned by root, a system account, or an approved application account. This is a finding only if any such directory is owned by an account other than root or an approved system or application account; determining whether a non-system (UID greater than 999) owner is an approved application account requires reviewer judgment and cannot be reliably automated.\n\nWorld-writable directories owned by an account with a UID greater than 999 (each line: owner, uid, perms, path):\n\n#{world_writable_dirs.empty? ? '(none found)' : world_writable_dirs}"
    end
  end
end
