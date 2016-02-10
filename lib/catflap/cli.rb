require "catflap"

module CatflapCli

  # Initialize catflap object
  def createCatflap
    begin
      @cf = Catflap.new @options[:config_file], @options[:noop], @options[:verbose]
    rescue Psych::SyntaxError
      puts "There is a YAML syntax error in your catflap configuration file.\n"
      exit 1
    rescue IOError => e
      puts "Configuration error: #{e.message}"
      exit 1
    end
  end

  def dispatchCommands command, arg
    # handle commands and options.
    begin
      @cf.print_version if @options[:version]

      case command
      when "start"
        start_server
      when "stop"
        stop_server
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
        grant arg
      when "revoke"
        revoke arg
      when "load"
        bulkload arg
      when "check"
        @cf.firewall.check_address arg
      when nil # catflap --version can be run with no command, so that's ok.
      else
        puts "Unrecognised command: there is no command #{command}"
        exit 1
      end
    rescue ArgumentError => err
      puts "Missing Argument: " << err.message
      exit 1
    end
  end

  def start_server
    require 'catflap/http'
    CfWebserver::start_server @cf
  end

  def stop_server
    require 'catflap/http'
    CfWebserver::stop_server
  end

  def grant ip
    if ip != nil
      @cf.firewall.add_address! ip
    else
      raise ArgumentError, "You must provide a valid IP address"
    end
  end

  def revoke ip
    if ip != nil
      @cf.firewall.delete_address! ip
    else
      raise ArgumentError, "You must provide a valid IP address"
    end
  end

  def check ip
    if ip != nil
      @cf.firewall.check_address ip
    else
      raise ArgumentError, "You must provide a valid IP address"
    end
  end

  def bulkload filename
    if filename != nil
      @cf.add_addresses_from_file! filename
    else
      raise ArgumentError, "You must provide a valid IP address"
    end
  end
end
