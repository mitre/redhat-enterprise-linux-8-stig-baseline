control 'SV-230311' do
  title 'RHEL 8 must disable the kernel.core_pattern.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 disables storing core dumps with the following commands:

$ sudo sysctl kernel.core_pattern

kernel.core_pattern = |/bin/false

If the returned line does not have a value of "|/bin/false", or a line is not returned and the need for core dumps is not documented with the information system security officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to restrict usage of ptrace to descendant processes by adding the following line to a dropfile in the "/etc/sysctl.d" directory:

Create a dropfile if it does not already exist:
$ sudo vi /etc/sysctl.d/99-disable-coredump.conf

Add the following to the file:
kernel.core_pattern = |/bin/false

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230311'
  tag rid: 'SV-230311r1155408_rule'
  tag stig_id: 'RHEL-08-010671'
  tag fix_id: 'F-32955r1155407_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  kernel_setting = 'kernel.core_pattern'
  kernel_expected_value = input('kernel_dump_expected_value')

  describe kernel_parameter(kernel_setting) do
    its('value') { should eq kernel_expected_value }
  end
end
