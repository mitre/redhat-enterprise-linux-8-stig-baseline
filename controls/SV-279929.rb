control 'SV-279929' do
  title 'RHEL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.'
  desc 'check', %q(Verify RHEL 8 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh

/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/'profile.d/ directory, is missing or is commented out, this is a finding.)
  desc 'fix', 'Configure RHEL 8 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000029-GPOS-00010']
  tag gid: 'V-279929'
  tag rid: 'SV-279929r1156340_rule'
  tag stig_id: 'RHEL-08-020360'
  tag fix_id: 'F-84394r1156339_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'host'
  tag 'container'

  timeout = input('shell_session_timeout')

  # Match the manual check: grep -i tmout /etc/profile /etc/profile.d/*.sh
  # Collect every uncommented `TMOUT=<value>` assignment from the profile scripts.
  profile_files = ['/etc/profile'] + command('ls /etc/profile.d/*.sh 2>/dev/null').stdout.split("\n").map(&:strip).reject(&:empty?)

  tmout_regexp = /^\s*(?:(?:declare|export|typeset|readonly)\s+(?:-\S+\s+)*)?TMOUT\s*=\s*(?<value>\d+)/i

  tmout_settings = profile_files.each_with_object({}) do |path, settings|
    next unless file(path).exist?

    file(path).content.lines.each do |line|
      stripped = line.strip
      next if stripped.empty? || stripped.start_with?('#')

      match = tmout_regexp.match(line)
      settings[path] = match[:value].to_i if match
    end
  end

  describe 'The interactive shell session timeout (TMOUT)' do
    it 'should be set in a profile script under /etc/profile.d/ or in /etc/profile' do
      expect(tmout_settings).not_to be_empty, 'TMOUT is not set (or is commented out) in /etc/profile or any /etc/profile.d/*.sh script'
    end
  end

  tmout_settings.each do |path, value|
    describe "The TMOUT value configured in #{path}" do
      subject { value }
      it "should be #{timeout} seconds or less" do
        expect(value).to be <= timeout
      end
    end
  end
end
