control 'SV-230275' do
  title 'RHEL 8 must accept Personal Identity Verification (PIV) credentials.'
  desc 'The use of PIV credentials facilitates standardization and reduces the
    risk of unauthorized access.

    The DoD has mandated the use of the Common Access Card (CAC) to support
    identity management and personal authentication for systems covered under
    Homeland Security Presidential Directive (HSPD) 12, as well as making the CAC a
    primary component of layered protection for national security systems.'
  desc 'check', 'Verify RHEL 8 accepts PIV credentials.

    Check that the "opensc" package is installed on the system with the
    following command:

        $ sudo yum list installed opensc

        opensc.x86_64     0.19.0-5.el8     @anaconda

    Check that "opensc" accepts PIV cards with the following command:

        $ sudo opensc-tool --list-drivers | grep -i piv

          PIV-II     Personal Identity Verification Card

    If the "opensc" package is not installed and the "opensc-tool" driver
    list does not include "PIV-II", this is a finding.'
  desc 'fix', 'Configure RHEL 8 to accept PIV credentials.

    Install the "opensc" package using the following command:

        $ sudo yum install opensc'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000376-GPOS-00161'
  tag gid: 'V-230275'
  tag rid: 'SV-230275r958816_rule'
  tag stig_id: 'RHEL-08-010410'
  tag fix_id: 'F-32919r567572_fix'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('smart_card_enabled')

    describe package('opensc') do
      it { should be_installed }
    end

    options = { assignment_regex: /^\s*(\S+)\s+(.*)$/ }
    opensc = command('opensc-tool --list-drivers').stdout
    opensc_conf = parse_config(opensc, options)

    piv_driver = input('piv_driver')

    describe 'OpenSC drivers' do
      it "should include '#{piv_driver}'" do
        expect(opensc_conf.params.keys).to include(piv_driver), "Missing '#{piv_driver}' in OpenSC driver list"
      end
    end
  else
    impact 0.0
    describe 'The system is not utilizing smart card authentication' do
      skip 'The system is not utilizing smart card authentication, this control is Not Applicable.'
    end
  end
end
