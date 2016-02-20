require 'catflap/firewall'

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

class Netfilter
  include Firewall

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
    @chain_allow = @chain + '-ALLOW'
    @chain_deny = @chain + '-DENY'
  end

  # Implementation of method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.

  def install_rules!
    output = "iptables -t nat -N #{@chain_allow}\n" # Create a new chain on the NAT table for our catflap netfilter allow rules.
    output << "iptables -t nat -N #{@chain_deny}\n" # Create a chain for the deny/reject rules.

    output << "iptables -t nat -A PREROUTING -p tcp -m multiport --dport #{@dports} -j #{@chain_allow}\n"
    output << "iptables -t nat -A PREROUTING -p tcp -m multiport --dport #{@dports} -j #{@chain_deny}\n"
    output << "iptables -t nat -A #{@chain_deny} -p tcp -m multiport --dport #{@dports} -j LOG\n" if @log_rejected
    output << "iptables -t nat -A #{@chain_deny} -p tcp -m multiport --dport #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"

    unless @accept_local
      output << "iptables -t nat -A OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j #{@chain_allow}\n"
      output << "iptables -t nat -A OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j #{@chain_deny}\n"
    end

    execute! output
  end

  # Implementation of method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.

  def uninstall_rules!
    output = "iptables -t nat -D PREROUTING -p tcp -m multiport --dport #{@dports} -j #{@chain_allow}\n"
    output << "iptables -t nat -D PREROUTING -p tcp -m multiport --dport #{@dports} -j #{@chain_deny}\n"

    unless @accept_local
      # This additional rule is required to trap the local output redirect.
      output << "iptables -t nat -D OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j #{@chain_allow}\n"
      output << "iptables -t nat -D OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j #{@chain_deny}\n"
    end

    output << "iptables -t nat -F #{@chain_allow}\n" # Flush the catflap allow chain
    output << "iptables -t nat -F #{@chain_deny}\n" # Flush the catflap deny chain
    output << "iptables -t nat -X #{@chain_allow}\n" # Remove the catflap allow chain
    output << "iptables -t nat -X #{@chain_deny}\n" # Remove the catflap deny chain

    execute! output
  end

  # Implementation of method to purge all rules from CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def purge_rules!
    execute! "iptables -t nat -F #{@chain_allow}"
  end

  # Implementation of method to list rules in CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def list_rules
     execute! "iptables -t nat -S #{@chain_allow}"
  end

  # Implementation of method to check the CATFLAP-ALLOW chain for an allowed IP.
  # @return [Boolean] true indicates that IP address already has access.

  def check_address ip
    assert_valid_ipaddr ip
    execute_true? "iptables -t nat -C #{@chain_allow} -s #{ip} -p tcp -m multiport --dport #{@dports} -j ACCEPT\n"
  end

  # Implementation of method to add/grant an IP access in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def add_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -I #{@chain_allow} 1 -s #{ip} -p tcp -m multiport --dport #{@dports} -j ACCEPT\n"
  end

  # Implementation of method to delete/revoke access for an IP in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.

  def delete_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -D #{@chain_allow} -s #{ip} -p tcp -m multiport --dport #{@dports} -j ACCEPT\n"
  end

end
