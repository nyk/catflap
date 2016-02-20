require 'spec_helper'

config_path = 'spec/config-files/iptables.yaml'

describe Catflap do
  before :each do
    @cf = Catflap.new(config_path, true, true)
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
    expect(@cf.firewall.assert_valid_ipaddr "1.179.248.226").to eq("1.179.248.226")
  end

  it 'identifies invalid ip input' do
    expect { @cf.firewall.assert_valid_ipaddr "this is bad &&&"}.to raise_error(Resolv::ResolvError)
  end

  it 'can print install rules' do
    rules = <<RULES
iptables -N CATFLAP-ALLOW
iptables -N CATFLAP-DENY
iptables -A INPUT -p tcp -m multiport --dports 80,443 -j CATFLAP-ALLOWiptables -A INPUT -p tcp -m multiport --dports 80,443 -j CATFLAP-DENYiptables -A CATFLAP-ALLOW -s 127.0.0.1 -p tcp -m multiport --dports 80,443 -j ACCEPT
iptables -A CATFLAP-DENY -p tcp -m multiport --dports 80,443 -j LOG
iptables -A CATFLAP-DENY -p tcp -m multiport --dports 80,443 -j REJECT
RULES
    expect{@cf.firewall.install_rules!}.to output(rules).to_stdout
  end

  it 'can print uninstall rules' do
    @cf.verbose = true
    rules = <<RULES
iptables -D INPUT -p tcp -m multiport --dports 80,443 -j CATFLAP-ALLOW
iptables -D INPUT -p tcp -m multiport --dports 80,443 -j CATFLAP-DENY
iptables -F CATFLAP-ALLOW
iptables -X CATFLAP-ALLOW
iptables -F CATFLAP-DENY
iptables -X CATFLAP-DENY
RULES
    expect{@cf.firewall.uninstall_rules!}.to output(rules).to_stdout
  end

  it 'can print purge rules' do
    @cf.verbose = true
    rules = "iptables -F CATFLAP-ALLOW\n"
    expect{@cf.firewall.purge_rules!}.to output(rules).to_stdout
  end

  it 'can print add address rules' do
    @cf.verbose = true
    rules = "iptables -I CATFLAP-ALLOW 1 -s 127.0.0.1 -p tcp -m multiport --dports 80,443 -j ACCEPT\n"
    expect{@cf.firewall.add_address! "127.0.0.1"}.to output(rules).to_stdout
  end

  it 'can print delete address rules' do
    @cf.verbose = true
    rules = "iptables -D CATFLAP-ALLOW -s 127.0.0.1 -p tcp -m multiport --dports 80,443 -j ACCEPT\n"
    expect{@cf.firewall.delete_address! "127.0.0.1"}.to output(rules).to_stdout
  end
end
