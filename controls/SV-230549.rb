control 'SV-230549' do
  title 'RHEL 8 must use reverse path filtering on all IPv4 interfaces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 uses reverse path filtering on IPv4 interfaces with the following commands:

$ sudo sysctl net.ipv4.conf.all.rp_filter

net.ipv4.conf.all.rp_filter = 1

If "net.ipv4.conf.all.rp_filter" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to use reverse path filtering on IPv4 interfaces by default.

Add or edit the following line in a single system configuration file in the "/etc/sysctl.d/" directory:

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_rp_filter.conf

net.ipv4.conf.all.rp_filter = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230549'
  tag rid: 'SV-230549r1184286_rule'
  tag stig_id: 'RHEL-08-040285'
  tag fix_id: 'F-33193r1184285_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  # Define the kernel parameter to be checked
  parameter = 'net.ipv4.conf.all.rp_filter'
  action = 'IPv4 reverse path filtering'
  value = 1

  # Get the current value of the kernel parameter
  current_value = kernel_parameter(parameter)

  # Check if the system is a Docker container
  if virtualization.system.eql?('docker')
    impact 0.0
    describe 'Control not applicable within a container' do
      skip 'Control not applicable within a container'
    end
  elsif input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else

    describe kernel_parameter(parameter) do
      it "is set to the required value for #{action}" do
        expect(current_value.value).to cmp value
        expect(current_value.value).not_to be_nil
      end
    end
  end
end
