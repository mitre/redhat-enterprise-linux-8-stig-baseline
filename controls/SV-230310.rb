control 'SV-230310' do
  title 'RHEL 8 must disable kernel dumps unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at
the time of the crash. Kernel core dumps may consume a considerable amount of
disk space and may result in denial of service by exhausting the available
space on the target file system partition.

    RHEL 8 installation media presents the option to enable or disable the
kdump service at the time of system installation.'
  desc 'check', 'Verify that kernel core dumps are disabled unless needed with the following
command:

    $ sudo systemctl status kdump.service

    kdump.service - Crash recovery kernel arming
    Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled; vendor
preset: enabled)
    Active: active (exited) since Mon 2020-05-04 16:08:09 EDT; 3min ago
    Main PID: 1130 (code=exited, status=0/SUCCESS)

    If the "kdump" service is active, ask the System Administrator if the use
of the service is required and documented with the Information System Security
Officer (ISSO).

    If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If kernel core dumps are not required, disable the "kdump" service with
the following command:

    # systemctl disable kdump.service

    If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230310'
  tag rid: 'SV-230310r1017120_rule'
  tag stig_id: 'RHEL-08-010670'
  tag fix_id: 'F-32954r567677_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  kernel_dump = input('kernel_dump_expected_value')

  if kernel_dump == '|/bin/false'
    describe systemd_service('kdump.service') do
      it { should_not be_running }
    end
  else
    describe systemd_service('kdump.service') do
      it { should be_running }
    end
  end
end
