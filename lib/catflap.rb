require 'catflap/version'
require 'yaml'
require 'ipaddr'
require 'resolv'
require 'digest'

class Catflap

  attr_accessor :print, :noop, :config
  attr_reader :fwplugin, :bind_addr, :port, :docroot, :endpoint, :dports, \
              :passphrases, :redir_protocol, :redir_hostname, :redir_port

  def initialize( file_path = nil )
    initialize_config file_path
    initialize_firewall_plugin
    load_passphrases
  end

  def initialize_config( file_path = nil )
    #file_path = file_path || '/usr/local/etc/catflap/config.yaml'

    # Set the default configuration values.
    @defaults = {
      "server" => {
        "listen_addr" => "0.0.0.0",
        "port" => 4777,
        "docroot" => "./ui",
        "endpoint" => "/catflap",
        "passfile" => nil,
        "redirect" => {
          "protocol" => "http",
          "hostname" => "json",
          "port" => 80
        }
      },
      "firewall" => {
        "plugin" => "iptables",
        "dports" => "80,443"
      }
    }

    if file_path != nil
      @config = YAML.load_file file_path if File.readable? file_path
      @bind_addr = get_config_value ['server','listen_addr']
      @port = get_config_value ['server','port']
      @docroot = get_config_value ['server','docroot']
      @endpoint = get_config_value ['server','endpoint']
      @passfile = get_config_value ['server','passfile']
      @redir_protocol = get_config_value ['server','redirect','protocol']
      @redir_hostname = get_config_value ['server','redirect','hostname']
      @redir_port = get_config_value ['server','redirect','port']
      @fwplugin = get_config_value ['firewall','plugin']
      @dports = get_config_value ['firewall','dports']
    else
      @config = defaults
      puts "There is no configuration file specifed. Using defaults."
    end

  end

  def get_config_value keys
    begin
      # Check to see if we have a value configured from file.
      overidden = keys.inject(@config, :fetch)
    rescue KeyError
      # No we don't, so look up the default value and return it.
      return keys.inject(@defaults, :fetch)
    end
    # A value was found in configuration file, so return that overidden value.
    return overidden
  end

  def initialize_firewall_plugin
    require_relative "catflap/plugins/firewall/#{@fwplugin}.rb"
    @firewall = Object.const_get(@fwplugin.capitalize).new(@config)
  end

  def load_passphrases
    if @passfile and File.readable? @passfile
      phrases = YAML.load_file @passfile
      @passphrases = phrases['passphrases']
    else
      raise IOError, "Cannot read the passfile: #{@passfile}!"
    end
  end

  def print_version
    puts "Catflap version #{Catflap::VERSION}"
  end

  def install_rules!
    execute! @firewall.install_rules
  end

  def uninstall_rules!
    execute! @firewall.uninstall_rules
  end

  def purge_rules!
    execute! @firewall.purge_rules
  end

  def list_rules
    system @firewall.list_rules
  end

  def check_address ip
    check_user_input ip
    return system @firewall.check_address ip
  end

  def add_address! ip
    check_user_input ip
    execute! @firewall.add_address ip
  end

  def delete_address! ip
    check_user_input ip
    execute! @firewall.delete_address ip
  end

  def add_addresses_from_file! filepath
    if File.readable? filepath
      output = ""
      File.open(filepath, "r").each_line do |ip|
        check_user_input ip
        output += @firewall.add_address ip.chomp
      end
      execute! output
    else
      raise IOError, "The file #{filepath} is not readable!"
    end
  end

  def execute! output
    puts output if @print
    unless @noop
      system output
    end
  end

  def check_user_input suspect
    begin
      ip = Resolv.getaddress(suspect)
    rescue Resolv::ResolvError
      ip = false
    end
  end

  def generate_token pass, salt
    Digest::SHA256.hexdigest pass + salt
  end

end
