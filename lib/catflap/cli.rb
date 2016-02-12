require "catflap"
require "catflap/http"

class CatflapCli
  include CfWebserver

  # Initialize catflap object
  def initialize options
      @options = options
      @cf = Catflap.new @options[:config_file], @options[:noop], @options[:verbose]
  end

  def dispatchCommands command, arg
    # handle commands and options.
    @cf.print_version if @options[:version]

    case command
    when "start"
      server_start @cf
    when "reload"
      @cf.load_passphrases
    when "purge"
      @cf.firewall.purge_rules!
    when "install"
      @cf.firewall.install_rules!
    when "uninstall"
      @cf.firewall.uninstall_rules!
    when "list"
      @cf.firewall.list_rules
    when "grant"
      raise ArgumentError, "You must provide a valid IP address" if arg == nil
      @cf.firewall.add_address! arg
    when "revoke"
      raise ArgumentError, "You must provide a valid IP address" if arg == nil
      @cf.firewall.delete_address! arg
    when "load"
      raise ArgumentError, "You must provide a file path" if arg == nil
      @cf.add_addresses_from_file! arg
    when "check"
      raise ArgumentError, "You must provide a valid IP address" if arg == nil
      @cf.firewall.check_address arg
    when nil # catflap --version can be run with no command, so that's ok.
    else
      raise NameError, "there is no command '#{command}'"
    end
  end

end
