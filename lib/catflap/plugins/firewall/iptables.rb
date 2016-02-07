class Iptables
  def initialize(config)
    @catflap_port = config['server']['port']
    @dports = config['firewall']['dports']
    @chain = config['firewall']['options']['chain'] || 'CATFLAP'
    @log_rejected = config['firewall']['options']['log_rejected'] || false
    @accept_local = config['firewall']['options']['accept_local'] || false
    @reject_policy = config['firewall']['options']['reject_policy'].to_sym || :drop
  end

  def install_rules
    output  = "iptables -N #{@chain}\n" # Create a new user-defined chain as a container for our catflap netfilter rules
    if @accept_local
      output << "iptables -A #{@chain} -s 127.0.0.1 -p tcp -m multiport --dports #{@dports} -j ACCEPT\n" # Accept packets from localhost
    end
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain}\n" # Jump from INPUT chain to the catflap chain
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Log any rejected packets to /var/log/messages
    case @reject_policy
    when :reject
      output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j REJECT\n"
    when :redirect # FIX-ME: this strategy does not work, need to rethink it. Need conditional redirect.
      unless @accept_local
        output << "iptables -t nat -A OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"
      end
      output << "iptables -t nat -A PREROUTING -p tcp -m multiport --dports #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"
    else # drop is the default
      output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j DROP\n" # Drop any other packets to the ports on the INPUT chain
    end
    return output.freeze
  end

  def uninstall_rules
    output  = "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain}\n" # Remove user-defined chain from INPUT chain
    output << "iptables -F #{@chain}\n" # Flush the catflap user-defined chain
    output << "iptables -X #{@chain}\n" # Remove the catflap chain
    output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Remove the logging rule
    case @reject_policy
    when :reject
      output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j REJECT\n"
    when :redirect
      unless @accept_local
        output << "iptables -t nat -D OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"
      end
      output << "iptables -D PREROUTING -t nat -p tcp -m multiport --dports #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"
    else # drop is the default
      output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j DROP\n" # Remove the packet dropping rule
    end
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
