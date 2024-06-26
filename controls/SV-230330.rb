control 'SV-230330' do
  title 'RHEL 8 must not allow users to override SSH environment variables.'
  desc 'SSH environment options potentially allow users to bypass access
restriction in some configurations.'
  desc 'check', %q(Verify that unattended or automatic logon via ssh is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permituserenvironment'

PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure RHEL 8 to allow the SSH daemon to not allow unattended or
automatic logon to the system.

    Add or edit the following line in the "/etc/ssh/sshd_config" file:

    PermitUserEnvironment no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-230330'
  tag rid: 'SV-230330r951610_rule'
  tag stig_id: 'RHEL-08-010830'
  tag fix_id: 'F-32974r567737_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This requirement is Not Applicable inside a container, the containers host manages the containers filesystems') {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_config do
    its('PermitUserEnvironment') { should eq 'no' }
  end
end
