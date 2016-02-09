require 'catflap/version'
require 'yaml'
require 'ipaddr'
require 'resolv'
require 'digest'

##
# Main library class.
class Catflap

  attr_accessor :print, :noop
  attr_reader :fwplugin, :bind_addr, :port, :docroot, :endpoint, :dports, \
              :passphrases, :redir_protocol, :redir_hostname, :redir_port

  def initialize( file_path = nil )
    initialize_config file_path
    initialize_firewall_plugin
    load_passphrases
  end

  def initialize_config( file_path = nil )
    file_path = file_path || "etc/config.yaml" # default config

    if File.readable? file_path
      @config = YAML.load_file file_path if File.readable? file_path
    else
      raise IOError, "Cannot read configuration file: #{file_path}"
    end

    @bind_addr = @config['server']['listen_addr']
    @port = @config['server']['port']
    @docroot = @config['server']['docroot']
    @endpoint = @config['server']['endpoint']
    @passfile = @config['server']['passfile']
    @redir_protocol = @config['server']['redirect']['protocol']
    @redir_hostname = @config['server']['redirect']['hostname']
    @redir_port = @config['server']['redirect']['port']
    @fwplugin = @config['firewall']['plugin']
    @dports = @config['firewall']['dports']
  end

  def initialize_firewall_plugin
    require_relative "catflap/plugins/firewall/#{@fwplugin}.rb"
    @firewall = Object.const_get(@fwplugin.capitalize).new @config
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
