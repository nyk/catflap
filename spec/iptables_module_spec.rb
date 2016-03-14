require 'spec_helper'
require 'netfilter/writer'
include NetfilterWriter

describe NetfilterWriter do
  before :all do
    @rules = Rules.new(:nat, '80,443')
    @rules.match('multiport')
  end

  it 'can make: add a chain rule' do
    expect(
      @rules.chain(:new, 'CATFLAP-ALLOW').flush
    ).to eq("iptables -t nat -N CATFLAP-ALLOW\n")
  end

  it 'can make: delete a chain rule' do
    expect(
      @rules.chain(:delete, 'CATFLAP-ALLOW').flush
    ).to eq("iptables -t nat -X CATFLAP-ALLOW\n")
  end

  it 'can make: flush a chain rule' do
    expect(
      @rules.chain(:flush, 'CATFLAP-ALLOW').flush
    ).to eq("iptables -t nat -F CATFLAP-ALLOW\n")
  end

  it 'can make: add a FORWARD rule' do
    expect(
      @rules
        .rule(:add, chain: 'PREROUTING', jump: 'REDIRECT', to_port: 4773).flush
    ).to eq(
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j REDIRECT --to-port 4773\n"
    )
  end

  it 'can make: add a LOG rule' do
    expect(
      @rules.rule(:add, chain: 'CATFLAP-DENY', jump: 'LOG').flush
    ).to eq(
      'iptables -t nat -A CATFLAP-DENY -p tcp -m multiport --dport 80,443' \
      " -j LOG\n"
    )
  end

  it 'can make: delete INPUT rule' do
    expect(
      @rules
        .table(:filter).rule(:delete, chain: 'INPUT', jump: 'CATFLAP-ALLOW')
        .flush
    ).to eq(
      'iptables -t filter -D INPUT -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-ALLOW\n"
    )
  end

  it 'can make: delete FORWARD rule' do
    expect(
      @rules
        .table(:nat).rule(:delete, chain: 'PREROUTING', jump: 'REDIRECT',
                                   to_port: 4773).flush
    ).to eq(
      'iptables -t nat -D PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j REDIRECT --to-port 4773\n"
    )
  end

  it 'can make: add ip rule' do
    expect(
      @rules
        .rule(:add, src: '127.0.0.1', chain: 'CATFLAP-ALLOW', jump: 'ACCEPT')
        .flush
    ).to eq(
      'iptables -t nat -A CATFLAP-ALLOW -s 127.0.0.1 -p tcp -m multiport' \
      " --dport 80,443 -j ACCEPT\n"
    )
  end

  it 'can make: chain two rules' do
    expect(
      @rules
        .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-ALLOW')
        .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-DENY')
        .flush
    ).to eq(
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-ALLOW\n" \
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-DENY\n"
    )
  end

  it 'can make: rename chain rule' do
    expect(
      @rules.chain(:rename, 'CATFLAP-DENY', to: 'CATFLAP-REJECT').flush
    ).to eq(
      "iptables -t nat -E CATFLAP-DENY CATFLAP-REJECT\n"
    )
  end

  it 'can identify: valid ip input' do
    expect(
      @rules
        .rule(:add, src: '8.8.8.8', chain: 'CATFLAP-ALLOW', jump: 'ACCEPT')
        .flush
    ).to eq(
      'iptables -t nat -A CATFLAP-ALLOW -s 8.8.8.8 -p tcp' \
      " -m multiport --dport 80,443 -j ACCEPT\n"
    )
  end

  it 'can identify: bad IP address' do
    expect do
      @rules
        .rule(:add, src: '127.0??;as', chain: 'CATFLAP-ALLOW',
                    jump: 'ACCEPT').flush
    end.to raise_error(Resolv::ResolvError)
  end

  it 'can switch contexts: table nat to filter and back again' do
    expect(
      @rules
      .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-ALLOW')
      .table('filter').rule(:add, chain: 'INPUT', jump: 'CATFLAP-ALLOW')
      .table('nat').rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-DENY')
      .flush
    ).to eq(
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-ALLOW\n" \
      'iptables -t filter -A INPUT -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-ALLOW\n" \
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-DENY\n" \
    )
  end

  it 'can switch contexts: chain to rule to chain' do
    expect(
      @rules
      .chain(:new, 'CATFLAP-DENY')
      .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-DENY')
      .chain(:new, 'CATFLAP-ALLOW')
      .flush
    ).to eq(
      "iptables -t nat -N CATFLAP-DENY\n" \
      'iptables -t nat -A PREROUTING -p tcp -m multiport --dport 80,443' \
      " -j CATFLAP-DENY\n" \
      "iptables -t nat -N CATFLAP-ALLOW\n"
    )
  end

  it 'can respond: to block that evaluates a true expression' do
    expect(
      @rules
      .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-ALLOW')
      .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-DENY')
      .rule(:add, chain: 'CATFLAP-DENY', jump: 'LOG') { true }
      .rule(:add, chain: 'OUTPUT -o lo', jump: 'CATFLAP-ALLOW')
      .flush
    ).to eq(
      'iptables -t nat -A PREROUTING -p tcp -m multiport' \
      " --dport 80,443 -j CATFLAP-ALLOW\n" \
      'iptables -t nat -A PREROUTING -p tcp -m multiport' \
      " --dport 80,443 -j CATFLAP-DENY\n" \
      'iptables -t nat -A CATFLAP-DENY -p tcp -m multiport' \
      " --dport 80,443 -j LOG\n" \
      'iptables -t nat -A OUTPUT -o lo -p tcp -m multiport' \
      " --dport 80,443 -j CATFLAP-ALLOW\n"
    )
  end

  it 'can respond: to block that evaluates a false expression' do
    expect(
      @rules
      .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-ALLOW')
      .rule(:add, chain: 'PREROUTING', jump: 'CATFLAP-DENY')
      .rule(:add, chain: 'CATFLAP-DENY', jump: 'LOG') { false }
      .rule(:add, chain: 'OUTPUT -o lo', jump: 'CATFLAP-ALLOW')
      .flush
    ).to eq(
      'iptables -t nat -A PREROUTING -p tcp -m multiport' \
      " --dport 80,443 -j CATFLAP-ALLOW\n" \
      'iptables -t nat -A PREROUTING -p tcp -m multiport' \
      " --dport 80,443 -j CATFLAP-DENY\n" \
      'iptables -t nat -A OUTPUT -o lo -p tcp -m multiport' \
      " --dport 80,443 -j CATFLAP-ALLOW\n"
    )
  end
end
