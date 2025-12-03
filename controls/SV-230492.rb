control 'SV-230492' do
  title 'RHEL 8 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository.'
  desc 'The EPEL is a repository of high-quality open-source packages for enterprise-class Linux distributions such as RHEL, CentOS, AlmaLinux, Rocky Linux, and Oracle Linux. These packages are not part of the official distribution but are built using the same Fedora build system to ensure compatibility and maintain quality standards.'
  desc 'check', 'Verify that RHEL 8 is not able to install packages from the EPEL with the following command:

$ dnf repolist
rhel-8-for-x86_64-appstream-rpms                      Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms                         Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
rhel-8-for-x86_64-baseos-source-rpms                  Red Hat Enterprise Linux 8 for x86_64 - BaseOS (Source RPMs)
rhel-8-for-x86_64-supplementary-rpms                  Red Hat Enterprise Linux 8 for x86_64 - Supplementary (RPMs)
satellite-tools-6.10-for-rhel-8-x86_64-rpms           Red Hat Satellite Tools 6.10 for RHEL 8 x86_64 (RPMs)

If any repositories containing the word "epel" in the name exist, this is a finding.'
  desc 'fix', 'The repo package can be manually removed with the following command:

$ sudo dnf remove epel-release

Configure the operating system to disable use of the EPEL repository with the following command:

$ sudo dnf config-manager --set-disabled epel'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000074-GPOS-00042']
  tag gid: 'V-230492'
  tag rid: 'SV-230492r1134888_rule'
  tag stig_id: 'RHEL-08-040010'
  tag fix_id: 'F-33136r1134887_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
  tag 'host'
  tag 'container'

  describe package('rsh-server') do
    it { should_not be_installed }
  end
end
