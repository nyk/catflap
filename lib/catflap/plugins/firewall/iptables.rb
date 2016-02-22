require 'catflap/plugins/firewall/plugin'
require 'catflap/firewall'

##
# A firewall plugin driver to implement rules on the NetFilter filter table.
#
# This driver passes rules to the filter table via the iptables user-space client.
# Two new chains are installed in the filter table, named by default:
# CATFLAP-DENY and CATFLAP-ALLOW. These are installed in the INPUT chain. You can
# configure the driver to install a LOG to log rejected packets, and also whether
# to REJECT or DROP denied packets.
#
# If you want to redirect to the Catflap server login port instead, then you
# should use the 'netfilter' driver instead, which is the default.
#
# @example firewall: plugin: 'iptables'
#
# @author Nyk Cowham <nykcowham@gmail.com>

class Iptables < FirewallPlugin
  include Firewall # Mixin to give us the execute! method

  # Initialize the driver class.
  # @param [Hash<String, Hash>] config associative array built by Catflap::initialize_config()
  # @param [Boolean] noop set to true to not send the commands to the firewall client.
  # @param [Boolean] verbose set to true to print the command output to stdout stream.
  # @return void

  def initialize config, noop, verbose
    @noop = noop
    @verbose = verbose
    @catflap_port = config['server']['port']
    @dports = config['firewall']['dports']
    @chain = config['firewall']['options']['chain'] || 'CATFLAP'
    @log_rejected = config['firewall']['options']['log_rejected'] || false
    @accept_local = config['firewall']['options']['accept_local'] || false
    @reject_policy = config['firewall']['options']['reject_policy'].to_sym || :drop
    @chain_allow = @chain + "-ALLOW"
    @chain_deny = @chain + "-DENY"
  end

  # Implementation of method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.

  def install_rules!
    output = "iptables -N #{@chain_allow}\n" # Create a chain for allow rules.
    output << "iptables -N #{@chain_deny}\n" # Create a chain for deny rules.
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain_allow}"
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain_deny}"

    if @accept_local
      output << "iptables -A #{@chain_allow} -s 127.0.0.1 -p tcp -m multiport --dports #{@dports} -j ACCEPT\n" # Accept packets from localhost
    end

    output << "iptables -A #{@chain_deny} -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Log any rejected packets to /var/log/messages

    jump = (@reject_policy == :reject) ? 'REJECT' : 'DROP'
    output << "iptables -A #{@chain_deny} -p tcp -m multiport --dports #{@dports} -j #{jump}\n"

    execute! output
  end

  # Implementation of method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.

  def uninstall_rules!
    output = "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain_allow}\n" # Remove allow chain from INPUT chain
    output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain_deny}\n" # Remove deny chain from INPUT chain
    output << "iptables -F #{@chain_allow}\n" # Flush the catflap allow chain
    output << "iptables -X #{@chain_allow}\n" # Remove the catflap allow chain
    output << "iptables -F #{@chain_deny}\n" # Flush the catflap deny chain
    output << "iptables -X #{@chain_deny}\n" # Remove the catflap deny chain

    execute! output
  end

  # Implementation of method to purge all rules from CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def purge_rules!
    execute! "iptables -F #{@chain_allow}"
  end

  # Implementation of method to list rules in CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def list_rules
    execute! "iptables -S #{@chain_allow}"
  end

  # Implementation of method to check the CATFLAP-ALLOW chain for an allowed IP.
  # @return [Boolean] true indicates that IP address already has access.

  def check_address ip
    assert_valid_ipaddr ip
    execute_true? "iptables -C #{@chain_allow} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

  # Implementation of method to add/grant an IP access in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def add_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -I #{@chain_allow} 1 -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

  # Implementation of method to delete/revoke access for an IP in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def delete_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -D #{@chain_allow} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

end
