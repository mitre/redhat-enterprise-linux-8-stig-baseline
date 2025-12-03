control 'SV-230503' do
  title 'RHEL 8 must be configured to disable USB mass storage.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity.'
  desc 'check', 'Verify the operating system disables the ability to load the USB Storage kernel module and ensure that the USB Storage kernel module is disabled with the following command:

$ sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"

/etc/modprobe.d/blacklist.conf:install usb-storage /bin/false
/etc/modprobe.d/blacklist.conf:blacklist usb-storage

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to disable the ability to use the USB Storage kernel module and the ability to use USB mass storage devices.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install usb-storage /bin/false
     blacklist usb-storage

Reboot the system for the settings to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163']
  tag gid: 'V-230503'
  tag rid: 'SV-230503r1069316_rule'
  tag stig_id: 'RHEL-08-040080'
  tag fix_id: 'F-33147r942935_fix'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  if input('usb_storage_required') == true
    describe kernel_module('usb_storage') do
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
  else
    describe kernel_module('usb_storage') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
