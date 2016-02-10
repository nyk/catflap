module Firewall

  def execute! output
    puts output if @print
    unless @noop
      system output
    end
  end

end
