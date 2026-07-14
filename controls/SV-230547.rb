control 'SV-230547' do
  title 'RHEL 8 must restrict exposed kernel pointer addresses access.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographic order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 is configured to restrict exposed kernel pointer address access.

Verify the runtime status of the "kernel.kptr_restrict" kernel parameter with the following command:

$ sudo sysctl kernel.kptr_restrict
kernel.kptr_restrict = 1

If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to restrict exposed kernel pointer addresses access.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_kptr_restrict.conf

Add the following to the file:
kernel.kptr_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230547'
  tag rid: 'SV-230547r1184283_rule'
  tag stig_id: 'RHEL-08-040283'
  tag fix_id: 'F-33191r1184282_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  # Define the kernel parameter to be checked
  parameter = 'kernel.kptr_restrict'
  action = 'kernel pointer addresses'
  value = 1

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  else

    describe kernel_parameter(parameter) do
      it "is set to #{value} for #{action}" do
        expect(current_value.value).to cmp value
        expect(current_value.value).not_to be_nil
      end
    end
  end
end
