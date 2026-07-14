control 'SV-279931' do
  title 'RHEL 8 must implement DOD-approved encryption in the bind package.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 8 incorporates systemwide crypto policies by default. The employed algorithms can be viewed in the /etc/crypto-policies/back-ends/ directory.

'
  desc 'check', %q(Note: If the "bind" package is not installed, this requirement is Not Applicable.

Verify BIND uses the system crypto policy with the following command:

$ sudo grep include /etc/named.conf

include "/etc/crypto-policies/back-ends/bind.config";'

If BIND is installed and the BIND config file does not contain the include "/etc/crypto-policies/back-ends/bind.config" directive, or the line is commented out, this is a finding.)
  desc 'fix', 'Configure BIND to use the system crypto policy.

Add the following line to the "options" section in "/etc/named.conf":

include "/etc/crypto-policies/back-ends/bind.config";'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-279931'
  tag rid: 'SV-279931r1184237_rule'
  tag stig_id: 'RHEL-08-010275'
  tag fix_id: 'F-84396r1156345_fix'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
  tag 'host'
  tag 'container'

  if package('bind').installed?
    impact 0.7

    # BIND must pull in the systemwide crypto policy via an active (uncommented)
    # include directive in /etc/named.conf. parse_config strips comments, so any
    # commented-out include line will not appear in the parsed content.
    named_conf = file('/etc/named.conf')

    describe named_conf do
      it { should exist }
    end

    if named_conf.exist?
      include_lines = parse_config(named_conf.content.to_s).content.lines.grep(/^\s*include\b/)

      describe 'The /etc/named.conf include directives' do
        it 'must reference the system crypto policy back-end (/etc/crypto-policies/back-ends/bind.config)' do
          expect(include_lines).to(include(match(%r{include\s+"?/etc/crypto-policies/back-ends/bind\.config"?\s*;})),
                                   "/etc/named.conf does not contain an active include for the system crypto policy.\n\tgot include lines: #{include_lines}")
        end
      end
    end
  else
    impact 0.0
    describe 'The bind package is not installed' do
      skip 'The "bind" package is not installed, this requirement is Not Applicable.'
    end
  end
end
