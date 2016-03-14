require 'catflap/firewall'
include Firewall

# Mixin module to add rule handling functions to netfilter-based drivers.
#
# @author Nyk Cowham <nykcowham@gmail.com>
module NetfilterWriter
  # Class providing a DSL for defining netfilter rules
  # @author Nyk Cowham <nykcowham@gmail.com>
  class Rules
    attr_accessor :noop, :verbose, :match

    def initialize(table, dports = nil)
      @table = table
      @dports = dports
      @match = nil
      @buffer = ''
    end

    # Chainable setter function: change the default table for rules.
    # @param [String] table the name of the table (e.g. 'nat', 'filter', etc.)
    # @return self
    def table(table)
      @table = table
      self
    end

    # Chainable setter function: change the default destination ports for rules.
    # @param [String] table the name of the table (e.g. 'nat', 'filter', etc.)
    # @return self
    def dports(dports)
      @dports = dports
      self
    end

    # Create, flush and delete chains and other iptable chain operations.
    # @param [Symbol] cmd the operation to perform (:new, :delete, :flush)
    # @param [String] chain name of the chain (e.g. INPUT, CATFLAP-DENY, etc.)
    # @param [Hash] p parameters for specific iptables features.
    # @return self
    # @example
    #   Rules.new('nat').chain(:list, 'MY-CHAIN', numeric: true).flush
    #   => "iptables -t nat -n -L MY-CHAIN"
    def chain(cmd, chain, p = {})
      cmds = {
        new: '-N', rename: '-E', delete: '-X', flush: '-F',
        list_rules: '-S', list: '-L', zero: '-Z', policy: '-P'
      }

      @buffer << [
        'iptables',
        option('-t', @table), cmds[cmd], option('-n', p[:numeric]), chain,
        option(false, p[:rulenum]), option(false, p[:to])
      ].compact.join(' ') << "\n"

      self
    end

    # Create, flush and delete chains
    # @param [String] cmd the operation to perform (add, delete, insert, etc.)
    # @param [Hash] p parameters for specific iptables features.
    # @param [Block] block will evaluate a block that will return true/false.
    # @return self
    def rule(cmd, p, &block)
      # Evaluate a block expression and return early if it evaluates to false.
      # If no block is passed it is equivalent to the block: { true }.
      return self if block_given? && !instance_eval(&block)

      raise ArgumentError, 'chain is a required argument' unless p[:chain]
      assert_valid_ipaddr(p[:src]) if p[:src]
      assert_valid_ipaddr(p[:dst]) if p[:dst]

      # Map of commands for rules
      cmds = {
        add: '-A', delete: '-D', insert: '-I', replace: '-R', check: '-C'
      }

      @buffer << [
        'iptables', option('-t', @table), cmds[cmd], p[:chain],
        option(false, p[:rulenum]), option('-f', p[:frag]),
        option('-s', p[:src]), option('-d', p[:dst]),
        option('-o', p[:out]), option('-i', p[:in]),
        option('-p', p[:proto] || 'tcp'), option('-m', p[:match] || @match),
        option('--sport', p[:sports] || @sports),
        option('--dport', p[:dports] || @dports), p[:jump] || p[:goto],
        option('--to-port', p[:to_port])
      ].compact.join(' ') << "\n"

      self
    end
  end

  def option(flag, value)
    return flag if value.is_a?(TrueClass)
    return flag.insert(0, '!') if value.is_a?(FalseClass)
    return value if flag.is_a?(FalseClass)
    flag << ' ' << value.to_s if flag && value
  end

  # Add a raw text rule, (e.g.: iptables -t nat CATFLAP-ALLOW ...)
  # @param [String] raw_rule custom raw iptables command.
  # @return self
  def raw(raw_rule)
    @buffer = raw_rule
    self
  end

  # Flush the rule buffer and output the resulting iptables commands.
  # @return [String] rule text that can be sent iptables user-space client.
  def flush
    out = @buffer
    @buffer = ''
    out
  end

  # Flush the rule and execute in iptables user-space client.
  # @return void
  def do
    execute flush
  end

  # Flush the rule and execute commands and return success/fail value.
  # @return [Boolean] true if the execution was successful.
  def do?
    execute_true? flush
  end
end
