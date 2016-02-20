require 'catflap/version'
require 'yaml'
require 'digest'

##
# Catflap controller class
#
# This class controls the initialization of the configuration file, setting
# options, initializing the firewall plugin driver and loading pass phrases.
#
# @author Nyk Cowham <nykcowham@gmail.com>

class Catflap
  # @!attribute noop
  #   @return [Boolean] true if no operation is to be performed.
  # @!attribute verbose
  #   @return [Boolean] true if command output should be written to stdout.
  # @!attribute [r] fwplugin
  #   @return [String] the name of the firewall driver plugin file and class.
  # @!attribute [r] bind_addr
  #   @return [String] the IP address the Catflap server should listen to.
  # @!attribute [r] port
  #   @return [Integer] the port number the Catflap server should listen to.
  # @!attribute [r] docroot
  #   @return [String] the file path location that HTML/CSS/JS files are located.
  # @!attribute [r] endpoint
  #   @return [String] the name of the REST service endpoint (e.g. /catflap).
  # @!attribute [r] dports
  #   @return [String] comma-separated list of ports to guard. (e.g. '80,443').
  # @!attribute [r] passphrases
  #   @return [Hash<String, String>] associative array of pass phrases. The key is the
  #     first word of the pass phrase where words are separated by a space or
  #     non-alphanumeric character (except for the underscore).
  # @!attribute [r] passfile
  #   @return [String] file path of the YAML file containg pass phrases.
  # @!attribute [r] token_ttl
  #   @return [Integer] the time-to-live in seconds before tokens expire.
  # @!attribute [r] redirect_url
  #   @return [String] a URL the browser should be redirect to after authentication.
  # @!attribute [r] firewall
  #   @return [Object, #install_rules!, #uninstall_rules!, #add_address!, #delete_address!, #purge_rules!, #list_rules, #check_address]
  #     a firewall object that is implemented by the firewall driver plugin.

  attr_accessor :verbose, :noop
  attr_reader :fwplugin, :bind_addr, :port, :docroot, :endpoint, :dports, \
              :passfile, :passphrases, :token_ttl, :redirect_url, :firewall

  # @param [String, nil] file_path file path of the YAML configuration file.
  # @param [Boolean] noop set to true to suppress destructive operations (no-operation).
  # @param [Boolean] verbose set to true to print operations to standard out stream.
  # @return [Catflap]

  def initialize( file_path = nil, noop = false, verbose = false )
    @noop = noop
    @verbose = verbose
    initialize_config file_path # TODO: integrate Configliere
    initialize_firewall_plugin
    load_passphrases
  end

  # Initialize the configuration options from the YAML configuration file.
  # @param [String, nil] file_path file path of the YAML configuration file.
  # @return void

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
    @token_ttl = @config['server']['token_ttl']
    @redirect_url = @config['server']['redirect_url'] || nil
    @fwplugin = @config['firewall']['plugin']
    @dports = @config['firewall']['dports']
  end

  # Initialize the firewall plugin driver.
  # @return void

  def initialize_firewall_plugin
    require_relative "catflap/plugins/firewall/#{@fwplugin}.rb"
    @firewall = Object.const_get(@fwplugin.capitalize).new @config, @noop, @verbose
  end

  # Load the pass phrase YAML file.
  # @raise [IOError] if the file is missing or not readable.
  # @return void

  def load_passphrases
    if @passfile and File.readable? @passfile
      phrases = YAML.load_file @passfile
      @passphrases = phrases['passphrases']
    else
      raise IOError, "Cannot read the passfile: #{@passfile}!"
    end
  end

  # Prints version information to stdout stream.
  # @return void

  def print_version
    puts "Catflap version #{Catflap::VERSION}"
  end

  # Generates a SHA256 encrypted token based on a passphrase and a timestamp
  # @param [String] pass the passphrase stored in passfile.
  # @param [String] salt a randomly generated number used to randomize the token.
  # @return [String] a token in the form of a SHA256 digest of a string.

  def generate_token pass, salt
    Digest::SHA256.hexdigest pass + salt
  end

end
