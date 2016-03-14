require 'catflap/firewall'
include Firewall

# Mixin module to add rule handling functions to netfilter-based drivers.
#
# @author Nyk Cowham <nykcowham@gmail.com>
module NetfilterWriter
  # Class providing a DSL for defining netfilter rules
  # @author Nyk Cowham <nykcowham@gmail.com>
  class Rules
    attr_accessor :noop, :verbose

    def initialize(table, ports = nil)
      @table = table
      @ports = ports
      @buffer = ''
    end

    def table(table)
      @table = table
      self
    end

    def ports(ports)
      @ports = ports
      self
    end

    def match(match)
      @match = match
      self
    end

    # Create, flush and delete chains
    # @param [String] cmd the operation to perform (add, delete, flush)
    # @param [String] chain name of the chain (e.g. INPUT, CATFLAP-DENY, etc.)
    # @return self
    def chain(cmd, chain, a = {})
      cmds = {
        new: '-N', rename: '-E', delete: '-X', flush: '-F',
        list_rules: '-S', list: '-L', zero: '-Z', policy: '-P'
      }
      table = build_option('-t', @table)
      numeric = build_option('-n', a[:numeric])
      rulenum = build_option(true, a[:rulenum])
      to = build_option(true, a[:to])
      @buffer << [
        'iptables', table, numeric, cmds[cmd], chain, rulenum, to
      ].compact.join(' ') << "\n"
      self
    end

    # Create, flush and delete chains
    # @param [String] cmd the operation to perform (add, delete, insert, etc.)
    # @param [String] chain name of the chain (e.g. INPUT, CATFLAP-DENY, etc.)
    # @return self
    def rule(cmd, a, &block)
      # Evaluate a block expression and return early if it evaluates to false.
      # If no block is passed it is equivalent to the block: { true }.
      return self if block_given? && !instance_eval(&block)

      raise ArgumentError, 'chain is a required argument' unless a[:chain]
      assert_valid_ipaddr(a[:src]) if a[:src]
      assert_valid_ipaddr(a[:dst]) if a[:dst]

      # Map of commands for rules
      cmds = {
        add: '-A', delete: '-D', insert: '-I', replace: '-R',
        check: '-C'
      }

      a[:proto] ||= 'tcp'
      table = build_option('-t', @table)
      jump = build_option('-j', a[:jump])
      goto = build_option('-g', a[:goto])
      proto = build_option('-p', a[:proto])
      inface = build_option('-i', a[:in])
      outface = build_option('-o', a[:out])
      src = build_option('-s', a[:src])
      dst = build_option('-d', a[:dst])
      match = build_option('-m', a[:match] || @match)
      ports = build_option('--dport', @ports)
      to_port = build_option('--to-port', a[:to_port])
      @buffer << [
        'iptables', table, cmds[cmd], a[:chain], src, dst, outface,
        inface, proto, match, ports, jump || goto, to_port
      ].compact.join(' ') << "\n"
      self
    end
  end

  def build_option(flag, value)
    return flag if value.is_a?(TrueClass)
    return value if flag.is_a?(TrueClass)
    return flag << ' ' << value.to_s if flag && value
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
