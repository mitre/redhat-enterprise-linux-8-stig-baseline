control 'SV-244527' do
  title 'RHEL 8 must have the packages required to use the hardware random
number generator entropy gatherer service.'
  desc 'The most important characteristic of a random number generator is its
randomness, namely its ability to deliver random numbers that are impossible to
predict.  Entropy in computer security is associated with the unpredictability
of a source of randomness.  The random source with high entropy tends to
achieve a uniform distribution of random values.  Random number generators are
one of the most important building blocks of cryptosystems.

    The rngd service feeds random data from hardware device to kernel random
device. Quality (non-predictable) random number generation is important for
several security functions (i.e., ciphers).'
  desc 'check', 'Note: For RHEL versions 8.4 and above running with kernel FIPS mode enabled as specified by RHEL-08-010020, this requirement is Not Applicable.

Check that RHEL 8 has the packages required to enabled the hardware random number generator entropy gatherer service with the following command:

$ sudo yum list installed rng-tools

rng-tools.x86_64                       6.8-3.el8                        @anaconda

If the "rng-tools" package is not installed, this is a finding.'
  desc 'fix', 'Install the packages required to enabled the hardware random number
generator entropy gatherer service with the following command:

    $ sudo yum install rng-tools'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-244527'
  tag rid: 'SV-244527r1017333_rule'
  tag stig_id: 'RHEL-08-010472'
  tag fix_id: 'F-47759r743829_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }
  only_if('This check does not apply to RHEL versions 8.4 or newer, if the system is RHEL version 8.3 or older, this check is applicable.', impact: 0.0) {
    (os.release.to_f) <= 8.3
}
  describe package('rng-tools') do
    it { should be_installed }
  end
end
