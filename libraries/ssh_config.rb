# copyright: 2015, Vulcano Security GmbH

require "inspec/utils/simpleconfig"
require "inspec/utils/file_reader"

class SshConfig < Inspec.resource(1)
    name "ssh_config"
    supports platform: "unix"
    supports platform: "windows"
    desc "Use the `ssh_config` InSpec audit resource to test OpenSSH client configuration data located at `/etc/ssh/ssh_config` on Linux and Unix platforms."
    example <<~EXAMPLE
        describe ssh_config do
        its('cipher') { should contain '3des' }
        its('port') { should eq '22' }
        its('hostname') { should include('example.com') }
        end
    EXAMPLE

    include FileReader

    def initialize(conf_path = nil, type = nil)
        @conf_path = conf_path || ssh_config_file("ssh_config")
        typename = (@conf_path.include?("sshd") ? "Server" : "Client")
        @type = type || "SSH #{typename} configuration #{conf_path}"
        read_content
    end

    def content
        read_content
    end

    def params(*opts)
        opts.inject(read_params) do |res, nxt|
        res.respond_to?(:key) ? res[nxt] : nil
        end
    end

    def convert_hash(hash)
        new_hash = {}
        hash.each do |k, v|
        new_hash[k.downcase] ||= v
        end
        new_hash
    end

    def method_missing(name)
        param = read_params[name.to_s.downcase]
        return nil if param.nil?
        # extract first value if we have only one value in array
        return param[0] if param.length == 1

        param
    end

    def to_s
        "SSH Configuration"
    end

    def resource_id
        @conf_path || "SSH Configuration"
    end

    private

    def read_content
        return @content if defined?(@content)

        @content = read_file_content(@conf_path)
    end

    def read_params
        return @params if defined?(@params)
        return @params = {} if read_content.nil?

        conf = SimpleConfig.new(
        read_content,
        assignment_regex: /^\s*(\S+?)\s+(.*?)\s*$/,
        multiple_values: true
        )
        @params = convert_hash(conf.params)
    end

    def ssh_config_file(type)
        if inspec.os.windows?
        programdata = inspec.os_env("programdata").content
        return "#{programdata}\\ssh\\#{type}"
        end

        "/etc/ssh/#{type}"
    end
end

class SshdConfig < SshConfig
  name "sshd_config"
  supports platform: "unix"
  supports platform: "windows"
  desc "Use the sshd_config InSpec audit resource to test configuration data for the Open SSH daemon located at /etc/ssh/sshd_config on Linux and UNIX platforms. sshd---the Open SSH daemon---listens on dedicated ports, starts a daemon for each incoming connection, and then handles encryption, authentication, key exchanges, command execution, and data exchanges."
  example <<~EXAMPLE
    describe sshd_config do
      its('Protocol') { should eq '2' }
    end
  EXAMPLE

  def initialize(path = nil)
    super(path || ssh_config_file("sshd_config"))
  end

  def to_s
    "SSHD Configuration"
  end

  private

  def ssh_config_file(type)
    if inspec.os.windows?
      programdata = inspec.os_env("programdata").content
      return "#{programdata}\\ssh\\#{type}"
    end

    "/etc/ssh/#{type}"
  end
end


class SshdActiveConfig < SshdConfig
    name "sshd_active_config"
    supports platform: "unix"
    supports platform: "windows"
    desc "Use the sshd_active_config InSpec audit resource to test configuration data for the Open SSH daemon located at /etc/ssh/sshd_config on Linux and UNIX platforms. sshd---the Open SSH daemon---listens on dedicated ports, starts a daemon for each incoming connection, and then handles encryption, authentication, key exchanges, command execution, and data exchanges."
    example <<~EXAMPLE
        describe sshd_active_config do
        its('Protocol') { should eq '2' }
        end
    EXAMPLE

    attr_reader :active_path
    def initialize()
      @active_path = dynamic_sshd_config_path()
      super(@active_path)
    end

    def to_s
        "SSHD Active Configuration (active path: #{@path})"
    end

    private

    def ssh_config_file(type)
        if inspec.os.windows?
            programdata = inspec.os_env("programdata").content
            return "#{programdata}\\ssh\\#{type}"
        end

            "/etc/ssh/#{type}"
        end
    end

    def dynamic_sshd_config_path
        command_output = ""
        error_output = ""
  
        if inspec.os.windows?
          # PowerShell script block to find the path of sshd.exe
          script = <<-EOH
        $sshdPath = (Get-Command sshd.exe).Source
        if ($sshdPath -ne $null) {
          Write-Output $sshdPath
        } else {
          Write-Error "sshd.exe not found"
        }
      EOH
          # Execute the PowerShell script block using InSpec's powershell resource
          sshd_path_result = inspec.powershell(script).stdout.strip
          sshd_path = "\"#{sshd_path_result}\""
          if !sshd_path_result.empty?
            command_output = inspec.command("#{sshd_path} -T").stdout
            error_output = inspec.command("#{sshd_path} -T").stderr
          else
            Inspec::Log.error("sshd.exe not found using PowerShell script block.")
            return nil
          end
        elsif inspec.os.unix?
          sshd_path = "/usr/sbin/sshd"
          command_output = inspec.command("#{sshd_path} -T").stdout
          error_output = inspec.command("#{sshd_path} -T").stderr
        end
  
        if error_output.empty?
          active_path =
            command_output
              .lines
              .find { |line| line.include?("configfile") }
              &.split
              &.last
        else
          if inspec.os.unix?
            command_output = inspec.command("sudo #{sshd_path} -dd 2>&1").stdout
            active_path =
              command_output
                .lines
                .find { |line| line.include?("filename") }
                &.split("filename")
                &.last
                &.strip
          else
            Inspec::Log.error(
              "Unable to determine sshd configuration path on Windows using -T flag."
            )
            return nil
          end
        end
  
        if active_path.nil? || active_path.empty?
          Inspec::Log.warn(
            "No active SSHD configuration found. Using default configuration."
          )
          return ssh_config_file("sshd_config") # Assuming ssh_config_file is a method that returns a default path
        end
        active_path
      end
    end
end