require 'yaml'
require 'ipaddr'

class Catflap
  Version = '1.0.0.pre'

  attr_accessor :print, :noop, :log_rejected
  attr_reader :fwplugin, :port, :docroot, :dports, :chain

  def initialize config_file
    config_file = config_file || '/usr/local/etc/catflap.yaml'
    @config = {}
    @config = YAML.load_file config_file if File.readable? config_file
    @port = @config['server']['port'] || 4777
    @docroot = @config['server']['docroot'] || './htdoc'
    @fwplugin = @config['firewall']['plugin'] || 'iptables'
    @chain = @config['firewall']['chain'] || 'catflap-accept'
    @dports = @config['firewall']['dports'] || '80,443'
    @print = false
    @noop = false
    @log_rejected = true
    initialize_firewall_plugin
  end

  def initialize_firewall_plugin
    require_relative "plugins/firewall/#{@fwplugin}.rb"
    @firewall = Object.const_get(@fwplugin.capitalize).new @config['firewall']
  end

  def print_version
    puts "Catflap version #{Version}"
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
      puts "The file #{filepath} is not readable!"
      exit 1
    end
  end

  def execute! output
    if @print then puts output end
    system output unless @noop
  end

  def check_user_input suspect
    return IPAddr.new(suspect)
  end

end
