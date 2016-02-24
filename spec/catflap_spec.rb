require 'spec_helper'

config_path = 'spec/config-files/iptables.yaml'

describe Catflap do
  before :each do
    @cf = Catflap.new(config_path, true, true)
  end

  it 'has a version number' do
    expect(Catflap::VERSION).not_to be nil
  end

  it 'can generate: valid token' do
    token = @cf.generate_token 'frisky kitten', '3404'
    expect(token).to eq(
      '72bbbf5556844e762af4897786827a3fcb1328d88cd69cef474d169a48358dfa'
    )
  end

  it 'can identify: valid ip input' do
    expect(@cf.firewall.assert_valid_ipaddr('8.8.8.8')).to eq('8.8.8.8')
  end

  it 'can identify: invalid ip input' do
    expect do
      @cf.firewall.assert_valid_ipaddr 'this is bad &&&'
    end.to raise_error(Resolv::ResolvError)
  end

  it 'can resolve: localhost' do
    expect(@cf.firewall.assert_valid_ipaddr('localhost')).to eq('127.0.0.1')
  end

  it 'can resolve: DNS record' do
    expect(@cf.firewall.assert_valid_ipaddr('www.example.com')).to eq(
      '93.184.216.34'
    )
  end

  # rubocop:disable Metrics/LineLength
  it 'can print: install rules' do
    rules = <<RULES
iptables -t filter -N CATFLAP-ALLOW
iptables -t filter -N CATFLAP-DENY
iptables -t filter -A INPUT -p tcp -m multiport --dport 80,443 -j CATFLAP-ALLOW
iptables -t filter -A INPUT -p tcp -m multiport --dport 80,443 -j CATFLAP-DENY
iptables -t filter -A CATFLAP-DENY -p tcp -m multiport --dport 80,443 -j LOG
iptables -t filter -A CATFLAP-DENY -p tcp -m multiport --dport 80,443 -j REJECT
iptables -t filter -A CATFLAP-ALLOW -s localhost -p tcp -m multiport --dport 80,443 -j ACCEPT
RULES
    expect { @cf.firewall.install_rules }.to output(rules).to_stdout
  end
  # rubocop:enable Metrics/LineLength

  it 'can print: uninstall rules' do
    @cf.verbose = true
    rules = <<RULES
iptables -t filter -D INPUT -p tcp -m multiport --dport 80,443 -j CATFLAP-ALLOW
iptables -t filter -D INPUT -p tcp -m multiport --dport 80,443 -j CATFLAP-DENY
iptables -t filter -F CATFLAP-ALLOW
iptables -t filter -X CATFLAP-ALLOW
iptables -t filter -F CATFLAP-DENY
iptables -t filter -X CATFLAP-DENY
RULES
    expect { @cf.firewall.uninstall_rules }.to output(rules).to_stdout
  end

  it 'can print: purge rules' do
    @cf.verbose = true
    rules = "iptables -t filter -F CATFLAP-ALLOW\n"
    expect { @cf.firewall.purge_rules }.to output(rules).to_stdout
  end

  it 'can print: add address rules' do
    @cf.verbose = true
    rules = 'iptables -t filter -I CATFLAP-ALLOW -s 127.0.0.1 -p tcp' \
      " -m multiport --dport 80,443 -j ACCEPT\n"
    expect { @cf.firewall.add_address '127.0.0.1' }.to output(rules).to_stdout
  end

  it 'can print: delete address rules' do
    @cf.verbose = true
    rules = 'iptables -t filter -D CATFLAP-ALLOW -s 127.0.0.1 -p tcp' \
      " -m multiport --dport 80,443 -j ACCEPT\n"
    expect do
      @cf.firewall.delete_address '127.0.0.1'
    end.to output(rules).to_stdout
  end
end
