require 'open3'
require 'resolv'

module Firewall

  def execute!(output)
    puts output if @verbose
    unless @noop
      out, err, _ = Open3.capture3 output << " 2>/dev/null"
      raise err if err != ""
      return out
    end
  end

  def execute_true?(output)
    _, err, _ = Open3.capture3 output << " 2>/dev/null"
    (err == "")
  end

  def assert_valid_ipaddr suspect
    Resolv.getaddress(suspect) # raises Resolv::ResolvError on bad IP.
  end

end
