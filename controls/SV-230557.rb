control 'SV-230557' do
  title 'If the Trivial File Transfer Protocol (TFTP) server is required, the
RHEL 8 TFTP daemon must be configured to operate in secure mode.'
  desc 'Restricting TFTP to a specific directory prevents remote users from
copying, transferring, or overwriting system files.'
  desc 'check', 'Verify the TFTP daemon is configured to operate in secure mode with the
following commands:

    $ sudo yum list installed tftp-server

    tftp-server.x86_64 x.x-x.el8

    If a TFTP server is not installed, this is Not Applicable.

    If a TFTP server is installed, check for the server arguments with the
following command:

    $ sudo grep server_args /etc/xinetd.d/tftp

    server_args = -s /var/lib/tftpboot

    If the "server_args" line does not have a "-s" option, and a
subdirectory is not assigned, this is a finding.'
  desc 'fix', 'Configure the TFTP daemon to operate in secure mode by adding the following
line to "/etc/xinetd.d/tftp" (or modify the line to have the required value):

    server_args = -s /var/lib/tftpboot'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230557'
  tag rid: 'SV-230557r1017319_rule'
  tag stig_id: 'RHEL-08-040350'
  tag fix_id: 'F-33201r568418_fix'
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
