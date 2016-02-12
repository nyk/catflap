require 'catflap/version'
require 'yaml'
require 'digest'

##
# Main library class.
class Catflap

  attr_accessor :verbose, :noop
  attr_reader :fwplugin, :bind_addr, :port, :docroot, :endpoint, :dports, \
              :passphrases, :redirect_url, :firewall

  def initialize( file_path = nil, noop = false, verbose = false )
    @noop = noop
    @verbose = verbose
    initialize_config file_path # TODO: integrate Configliere
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
    @redirect_url = @config['server']['redirect_url'] || nil
    @fwplugin = @config['firewall']['plugin']
    @dports = @config['firewall']['dports']
  end

  def initialize_firewall_plugin
    require_relative "catflap/plugins/firewall/#{@fwplugin}.rb"
    @firewall = Object.const_get(@fwplugin.capitalize).new @config, @noop, @verbose
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

  def generate_token pass, salt
    Digest::SHA256.hexdigest pass + salt
  end

end
