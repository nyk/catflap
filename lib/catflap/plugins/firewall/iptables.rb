require 'catflap/plugins/firewall/plugin'
require 'catflap/netfilter/rules'
include NetfilterRules

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
class Iptables < FirewallPlugin
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
    @t = Table.new(:filter, @dports)
  end

  # Method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.

  def install_rules
    jump = (@policy == :reject) ? 'REJECT' : 'DROP'
    output =
      @t.chain(:add, @allow) <<
      @t.chain(:add, @deny) <<
      @t.rule(:add, 'INPUT', @allow) <<
      @t.rule(:add, 'INPUT', @deny) <<
      @t.rule(:add, @deny, 'LOG') if @log_rejected
    output << @t.rule(:add, @deny, jump)
    output << @t.rule(:add, @allow, 'ACCEPT', 'localhost') if @accept_local
    execute output
  end

  # Method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.

  def uninstall_rules
    output =
      @t.rule(:delete, 'INPUT', @allow) <<
      @t.rule(:delete, 'INPUT', @deny) <<
      @t.chain(:flush, @allow) <<
      @t.chain(:delete, @allow) <<
      @t.chain(:flush, @deny) <<
      @t.chain(:delete, @deny)
    execute output
  end

  # Method to purge all rules from CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def purge_rules
    execute @t.chain(:flush, @allow)
  end

  # Method to list rules in CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def list_rules
    execute @t.chain(:list, @allow)
  end

  # Method to check the CATFLAP-ALLOW chain for an allowed IP.
  # @return [Boolean] true indicates that IP address already has access.

  def check_address(ip)
    execute_true? @t.rule(:check, @allow, 'ACCEPT', ip)
  end

  # Method to add/grant an IP access in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def add_address(ip)
    execute @t.rule(:insert, @allow, 'ACCEPT', ip)
  end

  # Method to delete/revoke access for an IP in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def delete_address(ip)
    execute @t.rule(:delete, @allow, 'ACCEPT', ip)
  end
end
