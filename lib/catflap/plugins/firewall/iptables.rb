require 'catflap/plugins/firewall/plugin'
require 'netfilter/writer'
include NetfilterWriter

##
# A firewall plugin driver to implement rules on the NetFilter filter table.
#
# This driver passes rules to the filter table via the iptables user-space
# client.Two new chains are installed in the filter table, named by default:
# CATFLAP-DENY and CATFLAP-ALLOW. These are installed in the INPUT chain. You
# can configure the driver to install a LOG to log rejected packets, and also
# whether to REJECT or DROP denied packets.
#
# If you want to redirect to the Catflap server login port instead, then you
# should use the 'netfilter' driver instead, which is the default.
#
# @example firewall: plugin: 'iptables'
#
# @author Nyk Cowham <nykcowham@gmail.com>
class IptablesDriver < FirewallPlugin
  # Initialize the driver class.
  # @param [Hash<String, Hash>] config built by Catflap::initialize_config()
  # @param [Boolean] noop set true to not send commands to firewall client.
  # @param [Boolean] verbose set true to print command output to stdout stream.
  # @return void
  def initialize(config, noop, verbose)
    super
    @chain = config['firewall']['options']['chain'] || 'CATFLAP'
    @log_rejected = config['firewall']['options']['log_rejected'] || false
    @accept_local = config['firewall']['options']['accept_local'] || false
    @policy = config['firewall']['options']['reject_policy'].to_sym || :drop
    @allow = @chain + '-ALLOW'
    @deny = @chain + '-DENY'
    @r = Rules.new(:filter, @dports)
    @r.match('multiport')
    @r.noop = noop
    @r.verbose = verbose
  end

  # Method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def install_rules
    target = (@policy == :reject) ? 'REJECT' : 'DROP'
    log = @log_rejected
    local = @accept_local
    @r.chain(:new, @allow)
      .chain(:new, @deny)
      .rule(:add, chain: 'INPUT', jump: @allow)
      .rule(:add, chain: 'INPUT', jump: @deny)
      .rule(:add, chain: @deny, jump: 'LOG') { log }
      .rule(:add, chain: @deny, jump: target)
      .rule(:add, chain: @allow, jump: 'ACCEPT',
                  src: 'localhost') { local }
      .do
  end

  # Method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def uninstall_rules
    @r.rule(:delete, chain: 'INPUT', jump: @allow)
      .rule(:delete, chain: 'INPUT', jump: @deny)
      .chain(:flush, @allow)
      .chain(:delete, @allow)
      .chain(:flush, @deny)
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
