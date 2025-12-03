control 'SV-230557' do
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, the
RHEL 8 TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from
copying, transferring, or overwriting system files.'
  desc 'check', 'Note: IAW RHEL-08-040190 if TFTP is not required, it should not be installed.  If TFTP is not installed, this rule is not applicable.

Check to see if TFTP server is installed with the following command:

$ sudo dnf list installed | grep tftp-server 
tftp-server.x86_64 x.x-x.el8

Verify that the TFTP daemon, if tftp.server is installed, is configured to operate in secure mode with the following command:

$ grep -i execstart /usr/lib/systemd/system/tftp.service
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

Note: The "-s" option ensures that the TFTP server only serves files from the specified directory, which is a security measure to prevent unauthorized access to other parts of the file system.

If the TFTP server is installed but the TFTP daemon is not configured to operate in secure mode, this is a finding.'
  desc 'fix', 'Configure the TFTP daemon to operate in secure mode with the following command:
$ sudo systemctl edit tftp.service

In the editor enter:
[Service]
ExecStart=/usr/sbin/in.tftpd -s /var/lib/tftpboot

After making changes, reload the systemd daemon and restart the TFTP service as follows:
$ sudo systemctl daemon-reload
$ sudo systemctl restart tftp.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230557'
  tag rid: 'SV-230557r1088855_rule'
  tag stig_id: 'RHEL-08-040350'
  tag fix_id: 'F-33201r1069173_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  if package('tftp-server').installed?
    impact 0.5
    describe command('grep server_args /etc/xinetd.d/tftp') do
      its('stdout.strip') { should match %r{^\s*server_args\s+=\s+(-s|--secure)\s(/\S+)$} }
    end
  else
    impact 0.0
    describe 'The TFTP package is not installed' do
      skip 'If a TFTP server is not installed, this is Not Applicable.'
    end
  end
end
