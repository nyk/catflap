require 'catflap/version'
require 'yaml'
require 'ipaddr'
require 'resolv'
require 'digest'

class Catflap

  attr_accessor :print, :noop, :config
  attr_reader :fwplugin, :port, :docroot, :dports, :passphrases, :redir_protocol, :redir_hostname, :redir_port

  def initialize config_file
    config_file = config_file || '/usr/local/etc/catflap/config.yaml'
    @config = {}
    @config = YAML.load_file config_file if File.readable? config_file
    @port = @config['server']['port'] || 4777
    @docroot = @config['server']['docroot'] || './ui'
    @passfile = @config['server']['passfile'] || nil
    @redir_protocol = @config['server']['redirect']['protocol'] || 'http'
    @redir_hostname = @config['server']['redirect']['hostname'] || nil
    @redir_port = @config['server']['redirect']['port'] || 80
    @fwplugin = @config['firewall']['plugin'] || 'iptables'
    @dports = @config['firewall']['dports'] || '80,443'
    initialize_firewall_plugin
    load_passphrases
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
      raise IOError, "Cannot read the passfile!"
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
