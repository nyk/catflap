require 'resolv'

module Firewall

  def execute! output
    puts output if @verbose
    unless @noop
      system output
    end
  end

  def assert_valid_ipaddr suspect
    ip = Resolv.getaddress(suspect) # raises Resolv::ResolvError on bad IP.
  end

end
