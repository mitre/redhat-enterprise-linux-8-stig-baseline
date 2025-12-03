control 'SV-230291' do
  title 'The RHEL 8 SSH daemon must not allow Kerberos authentication, except
to fulfill documented and validated mission requirements.'
  desc 'Configuring these settings for the SSH daemon provides additional
assurance that remote logon via SSH will not use unused methods of
authentication, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SSH daemon does not allow Kerberos authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*kerberosauthentication'

/etc/ssh/sshd_config:KerberosAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the information system security officer (ISSO), this is a finding.

If conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH daemon to not allow Kerberos authentication.

    Add the following line in "/etc/ssh/sshd_config", or uncomment the line
and set the value to "no":

    KerberosAuthentication no

    The SSH daemon must be restarted for the changes to take effect. To restart
the SSH daemon, run the following command:

    $ sudo systemctl restart sshd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230291'
  tag rid: 'SV-230291r1069303_rule'
  tag stig_id: 'RHEL-08-010521'
  tag fix_id: 'F-32935r743956_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !directory('/etc/ssh').exist?)
  }

  kerb = package('krb5-server')

  if (kerb.installed? && kerb.version >= '1.17-9.el8') || input('system_is_workstation')
    impact 0.0
    describe 'N/A' do
      skip 'The system is a workstation or is utilizing krb5-server-1.17-9.el8 or newer; control is Not Applicable.'
    end
  elsif input('kerberos_required')
    describe package('krb5-server') do
      it { should be_installed }
    end
  else
    describe sshd_active_config do
      its('KerberosAuthentication') { should cmp 'no' }
    end
  end
end
