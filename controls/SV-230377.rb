control 'SV-230377' do
  title 'RHEL 8 must prevent the use of dictionary words for passwords.'
  desc 'If RHEL 8 allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.'
  desc 'check', 'Verify RHEL 8 prevents the use of dictionary words for passwords.

Determine if the field "dictcheck" is set with the following command:

$ sudo grep -r dictcheck /etc/security/pwquality.conf*

/etc/security/pwquality.conf:dictcheck=1

If the "dictcheck" parameter is not set to "1", or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure RHEL 8 to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the /etc/pwquality.conf.d/ directory to contain the "dictcheck" parameter:

dictcheck=1

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-230377'
  tag rid: 'SV-230377r1017188_rule'
  tag stig_id: 'RHEL-08-020300'
  tag fix_id: 'F-33021r858788_fix'
  tag cci: ['CCI-000366', 'CCI-004066']
  tag nist: ['CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  setting = 'dictcheck'
  expected_value = 1

  describe 'pwquality.conf settings' do
    let(:config_files) do
      ['/etc/security/pwquality.conf'] +
        command("find /etc/security/pwquality.conf.d -maxdepth 1 -type f -name '*.conf' | sort").stdout.lines.map(&:strip)
    end

    let(:setting_value) do
      config_files.flat_map do |path|
        next [] unless file(path).file?

        config = parse_config_file(path, multiple_values: true)
        value = config.params[setting]
        value.is_a?(Integer) ? [value] : Array(value)
      end
    end

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is set more than once in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "sets `#{setting}` to #{expected_value}" do
      expect(setting_value.first.to_i).to eq(expected_value), "#{setting} is not set to #{expected_value} in pwquality.conf or pwquality.conf.d/*.conf"
    end
  end
end
