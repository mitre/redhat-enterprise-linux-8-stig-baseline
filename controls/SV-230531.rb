control 'SV-230531' do
  title 'The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the
console can reboot the system. If accidentally pressed, as could happen in the
case of a mixed OS environment, this can create the risk of short-term loss of
availability of systems due to unintentional reboot. In a graphical user
environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is
reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify RHEL 8 is configured to not reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ sudo grep -iR CtrlAltDelBurstAction /etc/systemd/system*
/etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction:CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to disable the CtrlAltDelBurstAction by adding it to a drop file in a "/etc/systemd/system.conf.d/" configuration file:

If no drop file exists, create one with the following command:

$ sudo mkdir -p /etc/systemd/system.conf.d && sudo vi /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction

Edit the file to contain the setting by adding the following text:

CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230531'
  tag rid: 'SV-230531r1155396_rule'
  tag stig_id: 'RHEL-08-040172'
  tag fix_id: 'F-33175r1155395_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  # V2R7 satisfies CtrlAltDelBurstAction=none set in /etc/systemd/system.conf
  # OR in any drop file under /etc/systemd/system.conf.d/ (recursive grep).
  describe command('grep -iR CtrlAltDelBurstAction /etc/systemd/system*') do
    its('stdout') { should match(/^[^:#]+:\s*CtrlAltDelBurstAction\s*=\s*none/i) }
  end
end
