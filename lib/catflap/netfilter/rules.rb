require 'catflap/firewall'
include Firewall

# Mixin module to add rule handling functions to netfilter-based drivers.
#
# @author Nyk Cowham <nykcowham@gmail.com>
module NetfilterRules
  # Class providing a DSL for defining netfilter rules
  # @author Nyk Cowham <nykcowham@gmail.com>
  class Table
    attr_accessor :ports

    def initialize(table, ports)
      @table = table
      @ports = ports
    end

    # Create, flush and delete chains
    # @param [String] op the operation to perform (add, delete, flush)
    # @param [String] table name of the netfilter table (e.g. nat, filter)
    # @param [String] chain name of the chain (e.g. INPUT, CATFLAP-DENY, etc.)
    # @return [String] the iptables command to be sent to the userspace client.
    def chain(op, chain)
      flg = case op
            when :add    then '-N'
            when :delete then '-X'
            when :flush  then '-F'
            when :list   then '-S'
            end
      tbl = @table.to_s
      "iptables -t #{tbl} #{flg} #{chain}\n"
    end

    # Create, flush and delete chains
    # @param [String] op the operation to perform (add, delete, flush)
    # @param [String] table name of the netfilter table (e.g. nat, filter)
    # @param [String] chain name of the chain (e.g. INPUT, CATFLAP-DENY, etc.)
    # @return [String] the iptables command to be sent to the userspace client.
    def rule(op, input, output, ip = nil)
      assert_valid_ipaddr(ip) if ip

      flg = case op
            when :add    then '-A'
            when :delete then '-D'
            when :insert then '-I'
            when :check  then '-C'
            end
      tbl = '-t ' + @table.to_s
      ports = '--dport ' + @ports
      proto = '-p tcp'
      multi = '-m multiport'

      input += ' -s ' + ip if ip

      "iptables #{tbl} #{flg} #{input} #{proto} " \
      "#{multi} #{ports} -j #{output}\n"
    end
  end
end
