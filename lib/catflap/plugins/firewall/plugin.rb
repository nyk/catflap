##
# Abstract class plugin driver to implement rules on the NetFilter filter table.
#
# Firewall drivers should inherit from this abstract class and implement each
# method. This serves as a contract for firewalls to follow to ensure that the
# driver can respond to firewall calls.
#
# @example firewall: plugin: 'iptables'
#
# @author Nyk Cowham <nykcowham@gmail.com>
class FirewallPlugin
  attr_reader :dports, :catflap_port

  def initialize(config, noop = false, verbose = false)
    @noop = noop
    @verbose = verbose
    @catflap_port = config['server']['port']
    @dports = config['firewall']['dports']
  end

  # Implement method to install the driver rules into iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def install_rules
    raise NotImplementedError
  end

  # Implement method to uninstall the driver rules from iptables.
  # @return void
  # @raise StandardError when iptables reports an error.
  def uninstall_rules
    raise NotImplementedError
  end

  # Implement method to purge all rules from CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def purge_rules
    raise NotImplementedError
  end

  # Implement method to list rules in CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def list_rules
    raise NotImplementedError
  end

  # Implement method to check the CATFLAP-ALLOW chain for an allowed IP.
  # @return [Boolean] true indicates that IP address already has access.
  def check_address(_)
    raise NotImplementedError
  end

  # Implement method to add/grant an IP access in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def add_address(_)
    raise NotImplementedError
  end

  # Implement method to delete/revoke access in the CATFLAP-ALLOW chain.
  # @return void
  # @raise StandardError when iptables reports an error.
  def delete_address(_)
    raise NotImplementedError
  end
end
