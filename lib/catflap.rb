require 'yaml'

class Catflap

  attr_accessor :chain, :dports, :print, :noop, :log_rejected

  def initialize(config_file = nil)
    @config = YAML.load_file(config_file) if config_file and File.exists?(config_file)
    @chain = (@config['rules']['chain']) ? @config['rules']['chain'] : "catflap-accept"
    @dports = (@config['rules']['dports']) ? @config['rules']['dports'] : "80,443"
    @print = false
    @noop = false
    @log_rejected = true
  end

  def install_rules!
    output  = "iptables -N #{@chain}\n" # Create a new user-defined chain as a container for our catflap netfilter rules
    output << "iptables -A #{@chain} -s 127.0.0.1 -p tcp -m multiport --dports #{@dports} -j ACCEPT\n" # Accept packets to localhost
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain}\n" # Jump from INPUT chain to the catflap chain
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j LOG\n" if @log_rejected # Log any rejected packets to /var/log/messages
    output << "iptables -A INPUT -p tcp -m multiport --dports #{@dports} -j DROP\n" # Drop any other packets to the ports on the INPUT chain
    execute!(output)
  end

  def uninstall_rules!
    output  = "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j #{@chain}\n" # Remove user-defined chain from INPUT chain
    output << "iptables -F #{@chain}\n" # Flush the catflap user-defined chain
    output << "iptables -X #{@chain}\n" # Remove the catflap chain
    output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j LOG\n" # Remove the logging rule
    output << "iptables -D INPUT -p tcp -m multiport --dports #{@dports} -j DROP\n" # Remove the packet dropping rule
    execute!(output)
  end

  def purge_rules!
    output = "iptables -F #{@chain}"
    execute!(output)
  end

  def list_rules
    system "iptables -S #{@chain}"
  end

  def check_address(ip)
    return system "iptables -C #{@chain} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
  end

  def add_address!(ip)
    output = "iptables -I #{@chain} 1 -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
    execute!(output)
  end

  def delete_address!(ip)
    output = "iptables -D #{@chain} -s #{ip} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
    execute!(output)
  end 

  def add_addresses_from_file!(filepath)
    if File.readable?(filepath)
      output = ""
      File.open(filepath, "r").each_line do |ip|
        output << "iptables -I #{@chain} 1 -s #{ip.chomp} -p tcp -m multiport --dports #{@dports} -j ACCEPT\n"
      end
      execute!(output)
    else
      puts "The file #{filepath} is not readable!"
      exit 1
    end
  end

  def execute!(output)
    if @print then puts output end
    system output unless @noop
  end 

end
