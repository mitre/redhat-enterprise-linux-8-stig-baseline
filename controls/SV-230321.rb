control 'SV-230321' do
  title 'All RHEL 8 local interactive user home directories must have mode 0750
or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users.'
  desc 'check', %q(Verify the assigned home directory of all local interactive users has a
mode of "0750" or less permissive with the following command:

    Note: This may miss interactive users that have been assigned a privileged
User Identifier (UID). Evidence of interactive use may be obtained from a
number of log files containing system logon information.

    $ sudo ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}'
/etc/passwd)

    drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

    If home directories referenced in "/etc/passwd" do not have a mode of
"0750" or less permissive, this is a finding.)
  desc 'fix', 'Change the mode of interactive user’s home directories to "0750". To
change the mode of a local interactive user’s home directory, use the following
command:

    Note: The example will be for the user "smithj".

    $ sudo chmod 0750 /home/smithj'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230321'
  tag rid: 'SV-230321r1017132_rule'
  tag stig_id: 'RHEL-08-010730'
  tag fix_id: 'F-32965r567710_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  exempt_home_users = input('exempt_home_users')
  expected_mode = input('home_dir_mode')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_homedirs = iuser_entries.homes.select { |home|
      file(home).more_permissive_than?(expected_mode)
    }
    describe 'All non-exempt interactive user account home directories on the system' do
      it "should not be more permissive than '#{expected_mode}'" do
        expect(failing_homedirs).to be_empty, "Failing home directories:\n\t- #{failing_homedirs.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
