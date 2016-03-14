require 'catflap/plugins/firewall/plugin'
require 'netfilter/writer'
include NetfilterWriter

##
# A firewall plugin driver to implement rules on the NetFilter NAT table.
#
# This driver passes rules to the NAT table via the iptables user-space client.
# Two new chains are installed in the NAT table, named by default:
# CATFLAP-DENY and CATFLAP-ALLOW. These are installed in the PREROUTING chain.
# You can configure the driver to install a LOG to log denied packets.
#
# This is the default and recommended driver for Linux systems running iptables.
#
# @example firewall: plugin: 'netfilter'
#
# @author Nyk Cowham <nykcowham@gmail.com>
class NetfilterDriver < FirewallPlugin
  # Initialize the driver class.
  # @param [Hash<String, Hash>] config hash: Catflap::initialize_config()
  # @param [Boolean] noop send the commands to the firewall client.
  # @param [Boolean] verbose print the command output to stdout stream.
  # @return void
  def initialize(config, noop = false, verbose = false)
    super
    @chain = config['firewall']['options']['chain'] || 'CATFLAP'
    @forward = config['firewall']['options']['forward']
    @log_rejected = config['firewall']['options']['log_rejected'] || false
    @accept_local = config['firewall']['options']['accept_local'] || false
    @allow = @chain + '-ALLOW'
    @deny = @chain + '-DENY'
    @r = Rules.new(:nat, @dports)
    @r.match('multiport')
    @r.noop = noop
    @r.verbose = verbose
  end

  # Method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def install_rules
    # We must make these local variables, so they are exposed to the blocks.
    log = @log_rejected
    deny_local = !@accept_local

    # Create a new chain on the NAT table for our catflap netfilter allow rules.
    @r.chain(:new, @allow)
      .chain(:new, @deny)
      .rule(:add, chain: 'PREROUTING', jump: @allow)
      .rule(:add, chain: 'PREROUTING', jump: @deny)
      .rule(:add, chain: @deny, jump: 'LOG') { log }
      .rule(:add, chain: 'OUTPUT', out: 'lo', jump: @allow) { deny_local }
      .rule(:add, chain: 'OUTPUT', out: 'lo', jump: @deny) { deny_local }

    @forward.each do |src, dest|
      src = src.to_s
      @r.rule(:add, chain: @deny, jump: 'REDIRECT', dports: src, to_port: dest)
    end
    @r.do
  end

  # Method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def uninstall_rules
    deny_local = !@accept_local

    @r.rule(:delete, chain: 'PREROUTING', jump: @allow)
      .rule(:delete, chain: 'PREROUTING', jump: @deny)
      .rule(:delete, chain: 'OUTPUT', out: 'lo',
                     jump: @allow) { deny_local }
      .rule(:delete, chain: 'OUTPUT', out: 'lo',
                     jump: @deny) { deny_local }
      .chain(:flush, @allow)
      .chain(:flush, @deny)
      .chain(:delete, @allow)
      .chain(:delete, @deny)
      .do
  end

  # Method to purge all rules from CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def purge_rules
    @r.chain(:flush, @allow).do
  end

  # Method to list rules in CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def list_rules
    @r.chain(:list, @allow).do
  end

  # Method to check the CATFLAP-ALLOW chain for an allowed IP.
  # @return [Boolean] true indicates that IP address already has access.
  def check_address(ip)
    @r.rule(:check, src: ip, chain: @allow, jump: 'ACCEPT').do?
  end

  # Method to add/grant an IP access in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def add_address(ip)
    @r.rule(:insert, src: ip, chain: @allow, jump: 'ACCEPT').do
  end

  # Method to delete/revoke access for an IP in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def delete_address(ip)
    @r.rule(:delete, src: ip, chain: @allow, jump: 'ACCEPT').do
  end
end
