require 'spec_helper'
require 'catflap/netfilter/rules'
include NetfilterRules

describe NetfilterRules do
  before :all do
    @nat = Table.new(:nat, '80,443')
    @filter = Table.new(:filter, '80,443')
  end

  it 'can make: add a chain rule' do
    rule = @nat.chain(:add, 'CATFLAP-ALLOW')
    expect(rule).to eq("iptables -t nat -N CATFLAP-ALLOW\n")
  end

  it 'can make: delete a chain rule' do
    rule = @nat.chain(:delete, 'CATFLAP-ALLOW')
    expect(rule).to eq("iptables -t nat -X CATFLAP-ALLOW\n")
  end

  it 'can make: flush a chain rule' do
    rule = @nat.chain(:flush, 'CATFLAP-ALLOW')
    expect(rule).to eq("iptables -t nat -F CATFLAP-ALLOW\n")
  end

  it 'can make: add a FORWARD rule' do
    r = @nat.rule(:add, 'PREROUTING', 'REDIRECT --to-port 4773')
    expect(r).to eq(
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j REDIRECT --to-port 4773\n"
    )
  end

  it 'can make: add a LOG rule' do
    r = @nat.rule(:add, 'CATFLAP-DENY', 'LOG')
    expect(r).to eq(
      'iptables -t nat -A CATFLAP-DENY -p tcp -m multiport --dport 80,443' \
      " -j LOG\n"
    )
  end

  it 'can make: delete INPUT rule' do
    r = @filter.rule(:delete, 'INPUT', 'CATFLAP-ALLOW')
    expect(r).to eq(
      'iptables -t filter -D INPUT -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-ALLOW\n"
    )
  end

  it 'can make: delete FORWARD rule' do
    r = @nat.rule(:delete, 'PREROUTING', 'REDIRECT --to-port 4773')
    expect(r).to eq(
      'iptables -t nat -D PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j REDIRECT --to-port 4773\n"
    )
  end

  it 'can make: add ip rule' do
    r = @nat.rule(:add, 'CATFLAP-ALLOW', 'ACCEPT', '127.0.0.1')
    expect(r).to eq(
      'iptables -t nat -A CATFLAP-ALLOW -s 127.0.0.1 -p tcp -m multiport' \
      " --dport 80,443 -j ACCEPT\n"
    )
  end

  it 'can identify: valid ip input' do
    expect(
      @nat.rule(:add, 'CATFLAP-ALLOW', 'ACCEPT', '8.8.8.8')
    ).to eq(
      'iptables -t nat -A CATFLAP-ALLOW -s 8.8.8.8 -p tcp' \
      " -m multiport --dport 80,443 -j ACCEPT\n"
    )
  end

  it 'can identify: bad IP address' do
    expect do
      @nat.rule(:add, 'CATFLAP-ALLOW', 'ACCEPT', '127.0??;as')
    end.to raise_error(Resolv::ResolvError)
  end
end
