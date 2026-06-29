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
  tag check_id: 'C-33218r1184284_chk'
  tag severity: 'medium'
  tag gid: 'V-230549'
  tag rid: 'SV-230549r1184286_rule'
  tag stig_id: 'RHEL-08-040285'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33193r1184285_fix'
  tag satisfies: ['SRG-OS-000420-GPOS-00186', 'SRG-OS-000142-GPOS-00076']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-001100', 'CCI-000366']
  tag nist: ['SC-5 a', 'SC-7 (2)', 'CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  parameter = 'net.ipv4.conf.all.rp_filter'
  value = 1
  regexp = /^\s*#{parameter}\s*=\s*#{value}\s*$/

  if input('ipv4_enabled') == false
    impact 0.0
    describe 'IPv4 is disabled on the system, this requirement is Not Applicable.' do
      skip 'IPv4 is disabled on the system, this requirement is Not Applicable.'
    end
  else
    describe kernel_parameter(parameter) do
      its('value') { should eq value }
    end

    search_results = command("/usr/lib/systemd/systemd-sysctl --cat-config | egrep -v '^(#|;)' | grep -F #{parameter}").stdout.strip.split("\n")

    correct_result = search_results.any? { |line| line.match(regexp) }
    incorrect_results = search_results.map(&:strip).reject { |line| line.match(regexp) }

    describe 'Kernel config files' do
      it "should configure '#{parameter}'" do
        expect(correct_result).to eq(true), 'No config file was found that correctly sets this action'
      end
      unless incorrect_results.nil?
        it 'should not have incorrect or conflicting setting(s) in the config files' do
          expect(incorrect_results).to be_empty, "Incorrect or conflicting setting(s) found:\n\t- #{incorrect_results.join("\n\t- ")}"
        end
      end
    end
  end
end
