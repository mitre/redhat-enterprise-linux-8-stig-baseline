control 'SV-230524' do
  title 'RHEL 8 must block unauthorized peripherals before establishing a
connection.'
  desc 'Without authenticating devices, unidentified or unknown devices may be
introduced, thereby facilitating malicious activity.

    Peripherals include, but are not limited to, such devices as flash drives,
external storage, and printers.

    A new feature that RHEL 8 provides is the USBGuard software framework. The
USBguard-daemon is the main component of the USBGuard software framework. It
runs as a service in the background and enforces the USB device authorization
policy for all USB devices. The policy is defined by a set of rules using a
rule language described in the usbguard-rules.conf file. The policy and the
authorization state of USB devices can be modified during runtime using the
usbguard tool.

    The System Administrator (SA) must work with the site Information System
Security Officer (ISSO) to determine a list of authorized peripherals and
establish rules within the USBGuard software framework to allow only authorized
devices.'
  desc 'check', 'Verify the USBGuard has a policy configured with the following command:

$ sudo usbguard list-rules

If the command does not return results or an error is returned, ask the SA to indicate how unauthorized peripherals are being blocked.
If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.

If the USBGuard package is not installed, ask the SA to indicate how unauthorized peripherals are being blocked.
If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.

If the system is a virtual machine with no virtual or physical USB peripherals attached, this is not a finding.'
  desc 'fix', 'Configure the operating system to enable the blocking of unauthorized
peripherals with the following command:
    This command must be run from a root shell and will create an allow list
for any usb devices currently connect to the system.

    # usbguard generate-policy > /etc/usbguard/rules.conf

    Note: Enabling and starting usbguard without properly configuring it for an
individual system will immediately prevent any access over a usb device such as
a keyboard or mouse'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag gid: 'V-230524'
  tag rid: 'SV-230524r1014813_rule'
  tag stig_id: 'RHEL-08-040140'
  tag fix_id: 'F-33168r744025_fix'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
 
  peripherals_package = input('peripherals_package')
  is_virtualized_system_no_usb_devices = input('is_virtualized_system_no_usb_devices')

  if is_virtualized_system_no_usb_devices
    impact 0.0
    describe 'The system is a virtual machine with no virtual or physical USB peripherals attached' do
      skip 'The system is a virtual machine with no virtual or physical USB peripherals attached, this control is Not Applicable.'
    end
  else
    if peripherals_package != 'usbguard'
      describe "Non-standard package #{peripherals_package}" do
        it 'is handling peripherals' do
          expect(peripherals_package).to exist
        end
      end
    else
      describe package('usbguard') do
        it { should be_installed }
      end
      describe command('usbguard list-rules') do
        its('stdout') { should_not be_empty }
        its('exit_status') { should eq 0 }
      end
    end
  end
end
