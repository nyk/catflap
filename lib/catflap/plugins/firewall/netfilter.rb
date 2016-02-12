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
  end

  def install_rules!
    output = "iptables -t nat -N #{@chain}\n" # Create a new chain on the NAT table for our catflap netfilter rules
    unless @accept_local
      output << "iptables -t nat -A OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j #{@chain}\n"
      output << "iptables -t nat -A OUTPUT -o lo -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected
      output << "iptables -t nat -A OUTPUT -o lo -p tcp -m multiport --dports #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"
    end
    output << "iptables -t nat -A PREROUTING -p tcp -m multiport --dports #{@dports} -j #{@chain}\n"
    output << "iptables -t nat -A PREROUTING -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected
    output << "iptables -t nat -A PREROUTING -p tcp -m multiport --dports #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"

    execute! output
  end

  def uninstall_rules!
    output  = "iptables -t nat -D PREROUTING -p tcp -m multiport --dports #{@dports} -j #{@chain}\n"

    unless @accept_local
      # This additional rule is required to trap the local output redirect.
      output << "iptables -t nat -D OUTPUT -o lo -p tcp -m multiport --dport #{@dports} -j #{@chain}\n"
      output << "iptables -t nat -D OUTPUT -o lo -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Remove the logging rule
      output << "iptables -t nat -D OUTPUT -o lo -p tcp -m multiport --dports #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"
    end

    output << "iptables -t nat -F #{@chain}\n" # Flush the catflap user-defined chain
    output << "iptables -t nat -X #{@chain}\n" # Remove the catflap chain
    output << "iptables -t nat -D PREROUTING -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Remove the logging rule
    output << "iptables -t nat -D PREROUTING -p tcp -m multiport --dports #{@dports} -j REDIRECT --to-port #{@catflap_port}\n"

    execute! output
  end

  def purge_rules!
    execute! "iptables -t nat -F #{@chain}"
  end

  def list_rules
    execute! "iptables -t nat -S #{@chain}", true
  end

  def check_address ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -C #{@chain} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

  def add_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -I #{@chain} 1 -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

  def delete_address! ip
    assert_valid_ipaddr ip
    execute! "iptables -t nat -D #{@chain} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

end
