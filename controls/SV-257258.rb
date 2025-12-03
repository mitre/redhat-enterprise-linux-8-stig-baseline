control 'SV-257258' do
  title 'RHEL 8.7 and higher must terminate idle user sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended.'
  desc 'check', 'Note: This requirement applies to RHEL versions 8.7 and higher. If the system is not RHEL version 8.7 or newer, this requirement is not applicable.

Note: For cloud hosted systems where "ClientAliveInterval" (V-244525) is configured, this setting is not applicable.

Verify that RHEL 8 logs out sessions that are idle for 10 minutes with the following command:

$ sudo grep -i ^StopIdleSessionSec /etc/systemd/logind.conf

StopIdleSessionSec=600

If "StopIdleSessionSec" is not configured to "600" seconds, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to log out idle sessions after 10 minutes by editing the /etc/systemd/logind.conf file with the following line:

StopIdleSessionSec=600

The "logind" service must be restarted for the changes to take effect. To restart the "logind" service, run the following command:

$ sudo systemctl restart systemd-logind'
  impact 0.5
  tag check_id: 'C-60942r1069265_chk'
  tag severity: 'medium'
  tag gid: 'V-257258'
  tag rid: 'SV-257258r1069328_rule'
  tag stig_id: 'RHEL-08-020035'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-60884r1014792_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'container'
  tag 'host'

  only_if('This check applies to RHEL versions 8.7 or newer, if the system is RHEL version 8.6  or below, this check is not applicable.', impact: 0.0) {
    (os.version.minor) >= 7
}
  stop_idle_session_sec = input('stop_idle_session_sec')

  describe parse_config_file('/etc/systemd/logind.conf') do
    its('Login') { should include('StopIdleSessionSec' => stop_idle_session_sec.to_s) }
  end
end
