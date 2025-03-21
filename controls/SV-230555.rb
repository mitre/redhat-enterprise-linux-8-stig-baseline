control 'SV-230555' do
  title 'RHEL 8 remote X connections for interactive users must be disabled
unless to fulfill documented and validated mission requirements.'
  desc %q(The security risk of using X11 forwarding is that the client's X11
display server may be exposed to attack when the SSH client requests
forwarding.  A system administrator may have a stance in which they want to
protect clients that may expose themselves to attack by unwittingly requesting
X11 forwarding, which can warrant a "no" setting.

    X11 forwarding should be enabled with caution. Users with the ability to
bypass file permissions on the remote host (for the user's X11 authorization
database) can access the local X11 display through the forwarded connection. An
attacker may then be able to perform activities such as keystroke monitoring if
the ForwardX11Trusted option is also enabled.

    If X11 services are not required for the system's intended function, they
should be disabled or restricted as appropriate to the system’s needs.)
  desc 'check', %q(Verify X11Forwarding is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*x11forwarding'

X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the  information system security officer (ISSO) as an operational requirement or is missing, this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the
"X11Forwarding" keyword and set its value to "no" (this file may be named
differently or be in a different location if using a version of SSH that is
provided by a third-party vendor):

    X11Forwarding no

    The SSH service must be restarted for changes to take effect:

    $ sudo systemctl restart sshd'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230555'
  tag rid: 'SV-230555r1017317_rule'
  tag stig_id: 'RHEL-08-040340'
  tag fix_id: 'F-33199r568412_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/ssh/sshd_config').exist?)
  }

  describe sshd_active_config do
    its('X11Forwarding') { should cmp 'no' }
  end
end
