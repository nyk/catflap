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
  # @!attribute [r] https
  #   @return [Hash<Symbol, String>] the HTTPS server configuration options.
  # @!attribute [r] daemonize
  #   @return [Boolean] true if the web server should run in the background.
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
  # @!attribute [r] pid_path
  #   @return [String] the path to the directory where the pid file should be written.
  # @!attribute [r] redirect_url
  #   @return [String] a URL the browser should be redirect to after authentication.
  # @!attribute [r] firewall
  #   @return [FirewallPlugin]
  #     a firewall object that is implemented by the firewall driver plugin.

  attr_accessor :verbose, :noop, :daemonize

  attr_reader :fwplugin, :bind_addr, :port, :docroot, :endpoint, :dports,
    :passfile, :passphrases, :token_ttl, :pid_path, :redirect_url, :firewall,
    :https

  # @param [String, nil] file_path file path of the YAML configuration file.
  # @param [Boolean] noop set to true to suppress destructive operations (no-operation).
  # @param [Boolean] verbose set to true to print operations to standard out stream.
  # @return [Catflap]

  def initialize(file_path = nil, noop = false, verbose = false)
    @noop = noop
    @verbose = verbose
    initialize_config file_path # TODO: integrate Configliere?
    initialize_firewall_plugin
    load_passphrases
  end

  # Initialize the configuration options from the YAML configuration file.
  # @param [String, nil] file_path file path of the YAML configuration file.
  # @return void

  def initialize_config(file_path = nil)

    # Look for config file in order of precedence.
    if !file_path
      ["~/.catflap", "/usr/local/etc/catflap", "/etc/catflap"].each do | loc |
        file = File.expand_path(loc + "/config.yaml")
        if File.readable? file
          file_path = file
          break
        end
      end
      # Use default config file if no overriding configuration was found.
      @config = YAML.load_file(file_path || "etc/config.yaml")
    end

    @bind_addr = @config['server']['listen_addr'] || '0.0.0.0'
    @port = @config['server']['port'] || 8778
    @docroot = @config['server']['docroot'] || './ui'
    @endpoint = @config['server']['endpoint'] || '/catflap'
    @passfile = @config['server']['passfile'] || './etc/passfile.yaml'
    @token_ttl = @config['server']['token_ttl'] || 15
    @pid_path = @config['server']['pid_path'] || '/var/run'
    @redirect_url = @config['server']['redirect_url'] || nil
    @https = @config['server']['https'] || {}
    @fwplugin = @config['firewall']['plugin'] || 'netfilter'
    @dports = @config['firewall']['dports'] || '80,443'
  end

  # Initialize the firewall plugin driver.
  # @return [FirewallPlugin] an object of a class inheriting from FirewallPlugin

  def initialize_firewall_plugin
    require_relative "catflap/plugins/firewall/#{@fwplugin}.rb"
    @firewall =
      Object.const_get(@fwplugin.capitalize).new @config, @noop, @verbose
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

  # Generates a SHA256 encrypted token based on a passphrase and a timestamp
  # @param [String] pass the passphrase stored in passfile.
  # @param [String] salt a randomly generated number used to randomize the token.
  # @return [String] a token in the form of a SHA256 digest of a string.

  def generate_token(pass, salt)
    Digest::SHA256.hexdigest pass + salt
  end

end
