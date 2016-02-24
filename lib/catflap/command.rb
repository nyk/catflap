require 'catflap'
require 'catflap/http'

##
# Command controller class.
#
# This class separates the implementation details of the command line
# interface from the actual interface. This allows for creating custom
# command tools by directly implementing this class.
# @author Nyk Cowham <nykcowham@gmail.com>
class CfCommand
  include CfWebserver

  # Initialize a new CatflapCli object
  # @param [Hash<String, String>] options an associative array of options
  #   read from the configuration file built by Catflap::initialize_config().
  # @return CatflapCli
  # @see Catflap - options are generated from file: Catflap::initialize_config()
  def initialize(options)
    @options = options
    @cf = Catflap.new(
      options[:config_file], options[:noop], options[:verbose]
    )
    @cf.daemonize = @options[:daemonize]
  end

  # A handler function to dispatch commands received from the front-end to the
  # firewall driver class or the Catflap web service.
  # @param [String] command the command that is to be executed.
  # @param [String] arg and argument for the command, (e.g. an IP address).
  # @return void
  # @raise ArgumentError when a required command argument is missing.
  # @raise NameError when the command is not recognized.
  # rubocop:disable Metrics/CyclomaticComplexity,Metrics/MethodLength
  # rubocop:disable Metrics/PerceivedComplexity,Metrics/AbcSize
  def dispatch_commands(command, arg)
    # handle commands and options.
    case command
    when 'version'
      "Catflap version #{Catflap::VERSION}"
    when 'start'
      server_start(@cf, @options[:https])
    when 'stop'
      server_stop(@cf, @options[:https])
    when 'status'
      server_status(@cf, @options[:https])
    when 'restart'
      begin
        server_stop(@cf, @options[:https])
        server_start(@cf, @options[:https])
      end
    when 'reload'
      @cf.load_passphrases
    when 'purge'
      @cf.firewall.purge_rules
    when 'install'
      @cf.firewall.install_rules
    when 'uninstall'
      @cf.firewall.uninstall_rules
    when 'list'
      puts @cf.firewall.list_rules
    when 'grant'
      raise ArgumentError, 'You must provide a valid IP address' if arg.nil?
      @cf.firewall.add_address(arg) unless @cf.firewall.check_address(arg)
    when 'revoke'
      raise ArgumentError, 'You must provide a valid IP address' if arg.nil?
      @cf.firewall.delete_address(arg) if @cf.firewall.check_address(arg)
    when 'check'
      raise ArgumentError, 'You must provide a valid IP address' unless arg
      return @cf.firewall.check_address(arg)
    when 'bulkload'
      raise ArgumentError, 'You must provide a file path' unless arg
      add_addresses_from_file(arg)
    when nil # catflap --version can be run with no command, so that's ok.
    else
      raise NameError, "there is no command '#{command}'"
    end
  end
  # rubocop:enable Metrics/CyclomaticComplexity,Metrics/MethodLength
  # rubocop:enable Metrics/PerceivedComplexity,Metrics/AbcSize

  # Handler function to bulkload IP's to the firewall.
  #
  # Checking that the file path points to readable file ensures that we can
  # safely accept the user-submitted parameter without any additional data
  # sanitization.
  # @param [String] filepath path to the bulkload file of IP addresses to add.
  # @return void
  # @raise IOError if the file cannot be found or is not readable.
  #
  # @note Every IP address in the file is validated to ensure that it resolves
  #   to a valid IP address.
  # @see Firewall Firewall::assert_valid_ipaddr(ip)
  def add_addresses_from_file(filepath)
    if File.readable? filepath
      File.open(filepath, 'r').each_line do |ip|
        @cf.firewall.add_address(ip.chomp)
      end
    else
      raise IOError, "The file #{filepath} is not readable!"
    end
  end
end
