require 'spec_helper'

config_path = 'etc/config.yaml'

describe Catflap do
  before :each do
    @cf = Catflap.new(config_path)
    @cf.noop = true
  end

  it 'has a version number' do
    expect(Catflap::VERSION).not_to be nil
  end

  it 'can print version' do
    expect {@cf.print_version}.to output("Catflap version #{Catflap::VERSION}\n").to_stdout
  end

  it 'generates valid token' do
    token = @cf.generate_token "frisky kitten", "3404"
    expect(token).to eq '72bbbf5556844e762af4897786827a3fcb1328d88cd69cef474d169a48358dfa'
  end

  it 'identifies valid ip input' do
    expect(@cf.check_user_input "1.179.248.226").to eq("1.179.248.226")
  end

  it 'identifies invalid ip input' do
    expect(@cf.check_user_input "this is bad &&&").to eq(false)
  end

  it 'can print install rules' do
    @cf.print = true
    rules = <<RULES
iptables -N CATFLAP
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j CATFLAP
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j LOG
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j REJECT
RULES
    expect{@cf.install_rules!}.to output(rules).to_stdout
  end

  it 'can print uninstall rules' do
    @cf.print = true
    rules = <<RULES
iptables -D INPUT -p tcp -m multiport --dports 80,443 -j CATFLAP
iptables -F CATFLAP
iptables -X CATFLAP
iptables -D INPUT -p tcp -m multiport --dports 80,443 -j LOG
iptables -D INPUT -p tcp -m multiport --dports 80,443 -j REJECT
RULES
    expect{@cf.uninstall_rules!}.to output(rules).to_stdout
  end

  it 'can print purge rules' do
    @cf.print = true
    rules = "iptables -F CATFLAP\n"
    expect{@cf.purge_rules!}.to output(rules).to_stdout
  end

  it 'can print add address rules' do
    @cf.print = true
    rules = "iptables -I CATFLAP 1 -s 127.0.0.1 -p tcp -m multiport --dports 80,443 -j ACCEPT\n"
    expect{@cf.add_address! "127.0.0.1"}.to output(rules).to_stdout
  end

  it 'can print delete address rules' do
    @cf.print = true
    rules = "iptables -D CATFLAP -s 127.0.0.1 -p tcp -m multiport --dports 80,443 -j ACCEPT\n"
    expect{@cf.delete_address! "127.0.0.1"}.to output(rules).to_stdout
  end
end
