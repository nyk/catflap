require 'catflap/plugins/firewall/plugin'
require 'catflap/netfilter/rules'
include NetfilterRules

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
class Netfilter < FirewallPlugin
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
    @t = Table.new(:nat, @dports)
  end

  # Method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def install_rules
    # Create a new chain on the NAT table for our catflap netfilter allow rules.
    output = @t.chain(:add, @allow) <<
             @t.chain(:add, @deny) <<
             @t.rule(:add, 'PREROUTING', @allow) <<
             @t.rule(:add, 'PREROUTING', @deny) <<
             @t.rule(:add, @deny, 'LOG') if @log_rejected

    unless @accept_local
      output <<
        @t.rule(:add, 'OUTPUT -o lo', @allow) <<
        @t.rule(:add, 'OUTPUT -o lo', @deny)
    end
    @forward.each do |src, dest|
      forward = "REDIRECT --to-port #{dest}"
      @t.ports = src.to_s # we are only adding a single forward port
      output << @t.rule(:add, @deny, forward)
    end

    execute output
  end

  # Method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def uninstall_rules
    output = @t.rule(:delete, 'PREROUTING', @allow) <<
             @t.rule(:delete, 'PREROUTING', @deny)

    unless @accept_local
      # This additional rule is required to trap the local output redirect.
      output <<
        @t.rule(:delete, 'OUTPUT -o lo', @allow) <<
        @t.rule(:delete, 'OUTPUT -o lo', @deny)
    end

    output <<
      @t.chain(:flush, @allow) <<
      @t.chain(:flush, @deny) <<
      @t.chain(:delete, @allow) <<
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
