control 'SV-230325' do
  title 'All RHEL 8 local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     $ sudo ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the smithj user, who has a home directory of "/home/smithj".

     $ sudo chmod 0740 /home/smithj/.<INIT_FILE>'
  impact 0.5
  tag check_id: 'C-32994r917877_chk'
  tag severity: 'medium'
  tag gid: 'V-230325'
  tag rid: 'SV-230325r1017136_rule'
  tag stig_id: 'RHEL-08-010770'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32969r917878_fix'
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-000366']
  tag nist: ['AC-3', 'CM-6 b']
  tag 'host'
  tag 'container'

  expected_mode = input('initialization_file_mode')
  init_file_names = %w[
    .bash_logout
    .bash_profile
    .bashrc
    .cshrc
    .kshrc
    .login
    .profile
    .tcshrc
  ]
  ignore_shells = input('non_interactive_shells').join('|')
  home_dirs = users.where { (uid == 0 || uid >= 1000) && !shell.match(ignore_shells) }.homes.uniq

  home_dirs.each do |home_dir|
    init_file_names.each do |init_file_name|
      init_file = file("#{home_dir}/#{init_file_name}")
      next unless init_file.exist?

      describe init_file do
        its('mode') { should cmp <= expected_mode }
      end
    end
  end
end
