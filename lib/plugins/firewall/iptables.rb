class Iptables
  def initialize firewall
    @chain = firewall['chain']
    @dports = firewall['dports']
    @log_rejected = firewall['log_rejected']
  end

  def install_rules rules
    chain = rules['chain']
    output  = "iptables -N #{@chain}\n" # Create a new user-defined chain as a container for our catflap netfilter rules
    output << "iptables -A #{@chain} -s 127.0.0.1 -p tcp -m multiport --dports #{@dports} -j ACCEPT\n" # Accept packets to localhost
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain}\n" # Jump from INPUT chain to the catflap chain
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Log any rejected packets to /var/log/messages
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j DROP\n" # Drop any other packets to the ports on the INPUT chain
    return output.freeze
  end

  def uninstall_rules
    output  = "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain}\n" # Remove user-defined chain from INPUT chain
    output << "iptables -F #{@chain}\n" # Flush the catflap user-defined chain
    output << "iptables -X #{@chain}\n" # Remove the catflap chain
    output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Remove the logging rule
    output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j DROP\n" # Remove the packet dropping rule
    return output.freeze
  end

  def purge_rules
    return "iptables -F #{@chain}".freeze
  end

  def list_rules
    return "iptables -S #{@chain}".freeze
  end

  def check_address ip
    return "iptables -C #{@chain} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n".freeze
  end

  def add_address ip
    return "iptables -I #{@chain} 1 -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n".freeze
  end

  def delete_address ip
    return "iptables -D #{@chain} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n".freeze
  end

end
