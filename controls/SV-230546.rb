control 'SV-230546' do
  title 'RHEL 8 must restrict usage of ptrace to descendant  processes.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore, may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

The sysctl --system command will load settings from all system configuration files. All configuration files are sorted by their filename in lexicographical order, regardless of which of the directories they reside in. If multiple files specify the same option, the entry in the file with the lexicographically latest name will take precedence. Files are read from directories in the following list from top to bottom. Once a file of a given filename is loaded, any file of the same name in subsequent directories is ignored.
/etc/sysctl.d/*.conf
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf'
  desc 'check', 'Verify RHEL 8 restricts usage of ptrace to descendant processes with the following commands:

$ sudo sysctl kernel.yama.ptrace_scope

kernel.yama.ptrace_scope = 1

If "kernel.yama.ptrace_scope" is not set to "1", is missing, or commented out, this is a finding.'
  desc 'fix', %q(Configure RHEL 8 to restrict usage of ptrace to descendant processes by adding the following line in a dropfile, in the "/etc/sysctl.d" directory with the following commands:

Create the dropfile if it doesn't already exist:
$ sudo vi /etc/sysctl.d/99-ptrace-restrict.conf

Add the following line to the file:
kernel.yama.ptrace_scope = 1

The system configuration files need to be reloaded for the changes to take effect. To reload the contents of the files, run the following command:

$ sudo sysctl --system)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230546'
  tag rid: 'SV-230546r1155413_rule'
  tag stig_id: 'RHEL-08-040282'
  tag fix_id: 'F-33190r1155412_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This system is acting as a router on the network, this control is Not Applicable', impact: 0.0) {
    !input('network_router')
  }

  # Define the kernel parameter to be checked
  parameter = 'kernel.yama.ptrace_scope'
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
      it "is set to #{value} in the running configuration" do
        expect(current_value.value).to cmp value
        expect(current_value.value).not_to be_nil
      end
    end
  end
end
