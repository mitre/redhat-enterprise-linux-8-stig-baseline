control 'SV-230478' do
  title 'RHEL 8 must have the packages required for encrypting offloaded audit
logs installed.'
  desc 'Information stored in one location is vulnerable to accidental or
incidental deletion or alteration.

    Off-loading is a common process in information systems with limited audit
storage capacity.

    RHEL 8 installation media provides "rsyslogd".  "rsyslogd" is a system
utility providing support for message logging.  Support for both internet and
UNIX domain sockets enables this utility to support both local and remote
logging.  Couple this utility with "rsyslog-gnutls" (which is a secure
communications library implementing the SSL, TLS and DTLS protocols), and you
have a method to securely encrypt and off-load auditing.

    Rsyslog provides three ways to forward message: the traditional UDP
transport, which is extremely lossy but standard; the plain TCP based
transport, which loses messages only during certain situations but is widely
available; and the RELP transport, which does not lose messages but is
currently available only as part of the rsyslogd 3.15.0 and above.
    Examples of each configuration:
    UDP *.* @remotesystemname
    TCP *.* @@remotesystemname
    RELP *.* :omrelp:remotesystemname:2514
    Note that a port number was given as there is no standard port for RELP.'
  desc 'check', 'Verify the operating system has the packages required for encrypting
offloaded audit logs installed with the following commands:

    $ sudo yum list installed rsyslog-gnutls

    rsyslog-gnutls.x86_64          8.1911.0-3.el8          @AppStream

    If the "rsyslog-gnutls" package is not installed, ask the administrator
to indicate how audit logs are being encrypted during offloading and what
packages are installed to support it.  If there is no evidence of audit logs
being encrypted during offloading, this is a finding.'
  desc 'fix', 'Configure the operating system to encrypt offloaded audit logs by
installing the required packages with the following command:

    $ sudo yum install rsyslog-gnutls'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230478'
  tag rid: 'SV-230478r1017268_rule'
  tag stig_id: 'RHEL-08-030680'
  tag fix_id: 'F-33122r744010_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') != ''
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  else
    describe package('rsyslog-gnutls') do
      it { should be_installed }
    end
  end
end
