control 'SV-279930' do
  title 'RHEL 8 IP tunnels must use FIPS 140-3-approved cryptographic algorithms.'
  desc 'Overriding the system crypto policy makes the behavior of the Libreswan service violate expectations and makes system configuration more fragmented.'
  desc 'check', 'Note: If the IPsec service is not installed, this is not applicable.

Verify the IPsec service uses the system crypto policy with the following command:

$ sudo grep include /etc/ipsec.conf /etc/ipsec.d/*.conf

/etc/ipsec.conf:include /etc/crypto-policies/back-ends/libreswan.config
/etc/ipsec.conf:include /etc/ipsec.d/*.conf

If the ipsec configuration file does not contain "include /etc/crypto-policies/back-ends/libreswan.config", this is a finding.'
  desc 'fix', 'Configure Libreswan to use the system cryptographic policy.

Add the following line to "/etc/ipsec.conf":

include /etc/crypto-policies/back-ends/libreswan.config'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag gid: 'V-279930'
  tag rid: 'SV-279930r1184239_rule'
  tag stig_id: 'RHEL-08-010280'
  tag fix_id: 'F-84395r1156342_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
  tag 'host'

  # The systemwide crypto policy and IP tunnels are host-OS/kernel-networking
  # concerns controlled by the host, not the container (mirrors the crypto-policies
  # family convention, e.g. SV-279932). Host-only with a container skip; and Not
  # Applicable when the IPsec service (libreswan) is not installed.
  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if !(package('libreswan').installed? || file('/etc/ipsec.conf').exist?)
    impact 0.0
    describe 'The IPsec service is not installed' do
      skip 'The IPsec service is not installed, this control is Not Applicable.'
    end
  else
    required_include = 'include /etc/crypto-policies/back-ends/libreswan.config'

    # Gather the IPsec configuration files: /etc/ipsec.conf and any
    # /etc/ipsec.d/*.conf files (matching the STIG check command).
    ipsec_conf_files = ['/etc/ipsec.conf'] + command('ls /etc/ipsec.d/*.conf 2>/dev/null').stdout.split("\n").reject(&:empty?)

    # Collect every "include" directive from all of the IPsec config files.
    include_lines = ipsec_conf_files.flat_map do |conf|
      f = file(conf)
      next [] unless f.exist?

      f.content.to_s.lines.map(&:strip).select { |l| l.start_with?('include') }
    end

    describe 'The IPsec/Libreswan configuration' do
      it "must include the system crypto policy back-end (#{required_include})" do
        present = include_lines.any? do |line|
          # Normalize internal whitespace before comparing.
          line.gsub(/\s+/, ' ').strip == required_include
        end
        expect(present).to eq(true), "The IPsec configuration files do not contain \"#{required_include}\".\n\tgot include directives: #{include_lines}"
      end
    end
  end
end
