require 'open3'
require 'resolv'

# Mixin module to add functions to firewall drivers that need them.
#
# It is methods in this module that must run with root privileges and at some
# point it may form the basis for a micro-service that runs with system
# privileges, so that the webserver can be run as a non-privileged user.
#
# @author Nyk Cowham <nykcowham@gmail.com>
module Firewall
  # Execute firewall commands in a forked process.
  # @param [String] output firewall command string to be forked and executed.
  # @return [String] any output returned by the forked process is returned.
  # @raise StandardError when the forked process returns an error.

  def execute(output)
    puts output if @verbose
    return if @noop

    out, err, = Open3.capture3 output << ' 2>/dev/null'
    raise err if err != ''
    out
  end

  # Execute firewall command in forked process to see if it emits an error.
  #
  # This is used by the 'check' command to see if an IP rule is already in the
  # firewall allow chain or not. It is to get around the quirkiness of the
  # netfilter -C check rule.
  # @param [String] output firewall command string to be forked and executed.
  # @return [Boolean] true if no error was returned from the forked process.

  def execute_true?(output)
    _, err, = Open3.capture3 output << ' 2>/dev/null'
    (err == '')
  end

  # Data validation method to ensure that user-submitted IP addresses can be
  # resolved to a valid IP address. This prevents any attempt at a shell/command
  # injection attack.
  # @param [String] suspect the user-submitted address to be validated.
  # @raise Resolve::ResolvError if string doesn't resolve to an IP address.

  def assert_valid_ipaddr(suspect)
    Resolv.getaddress(suspect) # raises Resolv::ResolvError on bad IP.
  end
end
