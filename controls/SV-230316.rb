control 'SV-230316' do
  title 'For RHEL 8 systems using Domain Name Servers (DNS) resolution, at
least two name servers must be configured.'
  desc 'To provide availability for name resolution services, multiple
redundant name servers are mandated. A failure in name resolution could lead to
the failure of security functions requiring name resolution, which may include
time synchronization, centralized authentication, and remote system logging.'
  desc 'check', %q(Note: If the system is running in a cloud platform and the cloud provider gives a single, highly available IP address for DNS configuration, this is not applicable.

Determine whether the system is using local or DNS name resolution with the following command:

$ sudo grep hosts /etc/nsswitch.conf

hosts: files dns

If the DNS entry is missing from the host's line in the "/etc/nsswitch.conf" file, the "/etc/resolv.conf" file must be empty.

Verify the "/etc/resolv.conf" file is empty with the following command:

$ sudo ls -al /etc/resolv.conf

-rw-r--r-- 1 root root 0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the "/etc/resolv.conf" file is not empty, this is a finding.

If the DNS entry is found on the host's line of the "/etc/nsswitch.conf" file, verify the operating system is configured to use two or more name servers for DNS resolution.

Determine the name servers used by the system with the following command:

$ sudo grep nameserver /etc/resolv.conf

nameserver 192.168.1.2
nameserver 192.168.1.3

If fewer than two lines are returned that are not commented out, this is a finding.)
  desc 'fix', 'Configure the operating system to use two or more name servers for DNS
resolution.

    By default, "NetworkManager" on RHEL 8 dynamically updates the
/etc/resolv.conf file with the DNS settings from active "NetworkManager"
connection profiles. However, this feature can be disabled to allow manual
configurations.

    If manually configuring DNS, edit the "/etc/resolv.conf" file to
uncomment or add the two or more "nameserver" option lines with the IP
address of local authoritative name servers. If local host resolution is being
performed, the "/etc/resolv.conf" file must be empty. An empty
"/etc/resolv.conf" file can be created as follows:

    $ sudo echo -n > /etc/resolv.conf'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230316'
  tag rid: 'SV-230316r1044801_rule'
  tag stig_id: 'RHEL-08-010680'
  tag fix_id: 'F-32960r567695_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  dns_in_host_line = parse_config_file('/etc/nsswitch.conf',
                                       comment_char: '#',
                                       assignment_regex: /^\s*([^:]*?)\s*:\s*(.*?)\s*$/).params['hosts'].include?('dns')

  unless dns_in_host_line
    describe 'If `local` resolution is being used, a `hosts` entry in /etc/nsswitch.conf having `dns`' do
      subject { dns_in_host_line }
      it { should be false }
    end
  end

  unless dns_in_host_line
    describe 'If `local` resoultion is being used, the /etc/resolv.conf file should' do
      subject { parse_config_file('/etc/resolv.conf', comment_char: '#').params }
      it { should be_empty }
    end
  end

  nameservers = parse_config_file('/etc/resolv.conf',
                                  comment_char: '#').params.keys.grep(/nameserver/)

  if dns_in_host_line
    describe "The system's nameservers: #{nameservers}" do
      subject { nameservers }
      it { should_not be nil }
    end
  end

  if dns_in_host_line
    describe 'The number of nameservers' do
      subject { nameservers.count }
      it { should cmp >= 2 }
    end
  end
end
