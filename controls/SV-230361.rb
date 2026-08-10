control 'SV-230361' do
  title 'RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

RHEL 8 utilizes "pwquality" as a mechanism to enforce password complexity. The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.'
  desc 'check', 'Check for the value of the "maxrepeat" option with the following command:

$ sudo grep -r maxrepeat /etc/security/pwquality.conf*

/etc/security/pwquality.conf:maxrepeat = 3

If the value of "maxrepeat" is set to more than "3" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

maxrepeat = 3

Remove any configurations that conflict with the above value.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag gid: 'V-230361'
  tag rid: 'SV-230361r1017173_rule'
  tag stig_id: 'RHEL-08-020150'
  tag fix_id: 'F-33005r858778_fix'
  tag cci: ['CCI-000195', 'CCI-004066']
  tag nist: ['IA-5 (1) (b)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  setting = 'maxrepeat'
  expected_value = input('maxrepeat')

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

    it "sets `#{setting}` to no more than #{expected_value}" do
      expect(setting_value.first.to_i).to be <= expected_value.to_i, "#{setting} is set to more than #{expected_value} in pwquality.conf or pwquality.conf.d/*.conf"
    end
  end
end
