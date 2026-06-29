control 'SV-230557' do
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, the RHEL 8 TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.'
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
  tag check_id: 'C-33226r1088854_chk'
  tag severity: 'medium'
  tag gid: 'V-230557'
  tag rid: 'SV-230557r1088855_rule'
  tag stig_id: 'RHEL-08-040350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-33201r1069173_fix'
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-000366']
  tag nist: ['CM-7 a', 'CM-6 b']
  tag 'host'
  tag 'container'

  if input('tftp_required')
    describe package('tftp-server') do
      it { should be_installed }
    end

    describe file('/usr/lib/systemd/system/tftp.service') do
      it { should exist }
      its('content') { should match(/ExecStart=.*\s-s(\s|$)/) }
    end
  else
    describe package('tftp-server') do
      it { should_not be_installed }
    end
  end
end
