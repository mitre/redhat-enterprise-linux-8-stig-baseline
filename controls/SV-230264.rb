control 'SV-230264' do
  title 'RHEL 8 must prevent the installation of software, patches, service
packs, device drivers, or operating system components from a repository without
verification they have been digitally signed using a certificate that is issued
by a Certificate Authority (CA) that is recognized and approved by the
organization.'
  desc 'Changes to any software components can have significant effects on the
overall security of the operating system. This requirement ensures the software
has not been tampered with and that it has been provided by a trusted vendor.

    Accordingly, patches, service packs, device drivers, or operating system
components must be signed with a certificate recognized and approved by the
organization.

    Verifying the authenticity of the software prior to installation validates
the integrity of the patch or upgrade received from a vendor. This verifies the
software has not been tampered with and that it has been provided by a trusted
vendor. Self-signed certificates are disallowed by this requirement. The
operating system should not have to verify the software again. This requirement
does not mandate DoD certificates for this purpose; however, the certificate
used to verify the software must be from an approved CA.'
  desc 'check', %q(Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that YUM verifies the signature of packages from a repository prior to install with the following command:

     $ sudo grep -E '^\[.*\]|gpgcheck' /etc/yum.repos.d/*.repo

     /etc/yum.repos.d/appstream.repo:[appstream]
     /etc/yum.repos.d/appstream.repo:gpgcheck=1
     /etc/yum.repos.d/baseos.repo:[baseos]
     /etc/yum.repos.d/baseos.repo:gpgcheck=1

If "gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified.

If there is no process to validate certificates that is approved by the organization, this is a finding.)
  desc 'fix', 'Configure the operating system to verify the signature of packages from a
repository prior to install by setting the following option in the
"/etc/yum.repos.d/[your_repo_name].repo" file:

    gpgcheck=1'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag gid: 'V-230264'
  tag rid: 'SV-230264r1017377_rule'
  tag stig_id: 'RHEL-08-010370'
  tag fix_id: 'F-32908r880710_fix'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  # TODO: create a plural resource for repo def files (`repositories`?)

  # get list of all repo files
  repo_def_files = command('ls /etc/yum.repos.d/*.repo').stdout.split("\n")

  if repo_def_files.empty?
    describe 'No repos found in /etc/yum.repos.d/*.repo' do
      skip 'No repos found in /etc/yum.repos.d/*.repo'
    end
  else
    # pull out all repo definitions from all files into one big hash
    repos = repo_def_files.map { |file| parse_config_file(file).params }.inject(&:merge)

    # check big hash for repos that fail the test condition
    failing_repos = repos.keys.reject { |repo_name| repos[repo_name]['gpgcheck'] == '1' }

    describe 'All repositories' do
      it 'should be configured to verify digital signatures' do
        expect(failing_repos).to be_empty, "Misconfigured repositories:\n\t- #{failing_repos.join("\n\t- ")}"
      end
    end
  end
end
