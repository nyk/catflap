require 'open3'
require 'resolv'

module Firewall

  def execute!(output, display=false)
    puts output if @verbose
    unless @noop
      out, err, status = Open3.capture3 output << " 2>/dev/null"
      puts out if display
      return (err != "")
    end
  end

  def assert_valid_ipaddr suspect
    Resolv.getaddress(suspect) # raises Resolv::ResolvError on bad IP.
  end

end
