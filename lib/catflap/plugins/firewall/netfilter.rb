require 'catflap/firewall'

class Netfilter
  include Firewall

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

  def purge_rules!
    execute! "iptables -t nat -F #{@chain_allow}"
  end

  def list_rules
     execute! "iptables -t nat -S #{@chain_allow}"
  end

  def check_address ip
    assert_valid_ipaddr ip
    execute_true? "iptables -t nat -C #{@chain_allow} -s #{ip} -p tcp -m multiport --dport #{@dports} -j ACCEPT\n"
  end

  def add_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -I #{@chain_allow} 1 -s #{ip} -p tcp -m multiport --dport #{@dports} -j ACCEPT\n"
  end

  def delete_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -D #{@chain_allow} -s #{ip} -p tcp -m multiport --dport #{@dports} -j ACCEPT\n"
  end

end
