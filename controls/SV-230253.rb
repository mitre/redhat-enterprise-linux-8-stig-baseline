control 'SV-230253' do
  title 'RHEL 8 must ensure the SSH server uses strong entropy.'
  desc 'The most important characteristic of a random number generator is its
randomness, namely its ability to deliver random numbers that are impossible to
predict.  Entropy in computer security is associated with the unpredictability
of a source of randomness.  The random source with high entropy tends to
achieve a uniform distribution of random values.  Random number generators are
one of the most important building blocks of cryptosystems.

    The SSH implementation in RHEL8 uses the OPENSSL library, which does not
use high-entropy sources by default.  By using the SSH_USE_STRONG_RNG
environment variable the OPENSSL random generator is reseeded from /dev/random.
 This setting is not recommended on computers without the hardware random
generator because insufficient entropy causes the connection to be blocked
until enough entropy is available.'
  desc 'check', 'Verify the operating system SSH server uses strong entropy with the
following command:

    Note: If the operating system is RHEL versions 8.0 or 8.1, this requirement
is not applicable.

    $ sudo grep -i ssh_use_strong_rng /etc/sysconfig/sshd

    SSH_USE_STRONG_RNG=32

    If the "SSH_USE_STRONG_RNG" line does not equal "32", is commented out
or missing, this is a finding.'
  desc 'fix', 'Configure the operating system SSH server to use strong entropy.

Add or modify the following line in the "/etc/sysconfig/sshd" file.

SSH_USE_STRONG_RNG=32

The SSH service must be restarted for changes to take effect.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230253'
  tag rid: 'SV-230253r627750_rule'
  tag stig_id: 'RHEL-08-010292'
  tag fix_id: 'F-32897r567506_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?)
  }

  if random_number_generator.is_software?
    impact 0.0
    desc 'justification': "The SSH_USE_STRONG_RNG setting relies on a hardware-based random number generator (HRNG) for sufficient entropy.
                          This system lacks a Hardware Random Number Generator (HRNG), causing possible issues with the connection stability."

    describe 'This control is Not Applicable as the SSH server is not using a hardware random number generator.' do
      skip 'This control is not applicable as the SSH server is not using a hardware random number generator.'
    end
  elsif os.version.minor.between?(0, 1)
    message = <<~MESSAGE
      \n\nThis requirement does not apply to RHEL versions 8.0 or 8.1.\n
      The system is running RHEL version: #{os.version}, this requirement is Not Applicable.
    MESSAGE

    impact 0.0
    describe message do
      skip message
    end
  else
    parameter = 'SSH_USE_STRONG_RNG'
    value = '32'
    file = '/etc/sysconfig/sshd'
    search_results = parse_config_file(file).params[parameter].to_i

    describe 'The SSH server must ensure it uses strong entropy' do
      it "and should configure '#{parameter}'" do
        expect(search_results).to cmp(32), "The SSH file: '/etc/sysconfig/sshd' does not have the #{parameter} set to #{value}, it is set to #{search_results}."
      end
    end
  end
end
