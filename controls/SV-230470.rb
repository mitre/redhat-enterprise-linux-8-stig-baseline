control 'SV-230470' do
  title 'RHEL 8 must enable Linux audit logging for the USBGuard daemon.'
  desc 'Without the capability to generate audit records, it would be
difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    If auditing is enabled late in the startup process, the actions of some
startup processes may not be audited. Some audit systems also maintain state
information only available if auditing is enabled before a given process is
created.

    Audit records can be generated from various components within the
information system (e.g., module or policy filter).

    The list of audited events is the set of events for which audits are to be
generated. This set of events is typically a subset of the list of all events
for which the system is capable of generating audit records.

    DoD has defined the list of events for which RHEL 8 will provide an audit
record generation capability as the following:

    1) Successful and unsuccessful attempts to access, modify, or delete
privileges, security objects, security levels, or categories of information
(e.g., classification levels);

    2) Access actions, such as successful and unsuccessful logon attempts,
privileged activities or other system-level access, starting and ending time
for user access to the system, concurrent logons from different workstations,
successful and unsuccessful accesses to objects, all program initiations, and
all direct access to the information system;

    3) All account creations, modifications, disabling, and terminations; and

    4) All kernel module load, unload, and restart actions.'
  desc 'check', 'Verify RHEL 8 enables Linux audit logging of the USBGuard daemon with the following commands:

Note: If the USBGuard daemon is not installed and enabled, this requirement is Not Applicable.

$ sudo grep -i auditbackend /etc/usbguard/usbguard-daemon.conf

AuditBackend=LinuxAudit

If the "AuditBackend" entry does not equal "LinuxAudit", is missing, or the line is commented out, this is a finding.

If the system is a virtual machine with no virtual or physical USB peripherals attached, this is not a finding.'
  desc 'fix', 'Configure RHEL 8 to enable Linux audit logging of the USBGuard daemon by
adding or modifying the following line in
"/etc/usbguard/usbguard-daemon.conf":

    AuditBackend=LinuxAudit'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-230470'
  tag rid: 'SV-230470r1017261_rule'
  tag stig_id: 'RHEL-08-030603'
  tag fix_id: 'F-33114r744005_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
  tag 'host'

  is_virtualized_system_no_usb_devices = input('is_virtualized_system_no_usb_devices')

  if is_virtualized_system_no_usb_devices
    impact 0.0
    describe 'The system is a virtual machine with no virtual or physical USB peripherals attached' do
      skip 'The system is a virtual machine with no virtual or physical USB peripherals attached, this control is Not Applicable.'
    end
  else
    # Control is Not Applicable if usbguard is not installed and enabled
    if (!(package('usbguard').installed? && service('usbguard').enabled?))
      impact 0.0
      describe 'The USBGuard service is not installed and enabled' do
        skip 'The USBGuard service is not installed and enabled, this control is Not Applicable.'
      end
    else
      # Check if usbguard is conducting audits
      describe parse_config_file('/etc/usbguard/usbguard-daemon.conf') do
        its('AuditBackend') { should cmp 'LinuxAudit' }
      end
    end
  end
end
