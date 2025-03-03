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
  desc 'check', 'Note: If the operating system is RHEL versions 8.0 or 8.1, this requirement is not applicable.

Verify the operating system SSH server uses strong entropy with the following command:

$ sudo grep -i ssh_use_strong_rng /etc/sysconfig/sshd

SSH_USE_STRONG_RNG=32

If the "SSH_USE_STRONG_RNG" line does not equal "32", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the operating system SSH server to use strong entropy.

Add or modify the following line in the "/etc/sysconfig/sshd" file.

SSH_USE_STRONG_RNG=32

The SSH service must be restarted for changes to take effect.

Restart the SSH Daemon with the following command:

$ sudo systemctl restart sshd.service'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-230253'
  tag rid: 'SV-230253r1044799_rule'
  tag stig_id: 'RHEL-08-010292'
  tag fix_id: 'F-32897r1044798_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  message = <<~MESSAGE
    \n\nThis check only applies to RHEL versions 8.0 or 8.1.\n
    The system is running RHEL version: #{os.version}, this requirement is Not Applicable.
  MESSAGE
  only_if(message, impact: 0.0) do
    os.version.minor.between?(0, 1)
  end

  if virtualization.system.eql?('docker') && !file('/etc/sysconfig/sshd').exist?
    impact 0.0
    describe 'Control not applicable - SSH is not installed within containerized RHEL' do
      skip 'Control not applicable - SSH is not installed within containerized RHEL'
    end
  else
    describe parse_config_file('/etc/sysconfig/sshd') do
      its('SSH_USE_STRONG_RNG') { should cmp 32 }
    end
  end
end
