require 'spec_helper'

config_path = 'etc/config.yaml'

describe Catflap do
  before :all do
    @cf = Catflap.new(config_path)
    @cf.noop = true
  end

  it 'can configure bind_addr from file' do
    expect(@cf.bind_addr).to eq("0.0.0.0")
  end

  it 'can configure port from file' do
    expect(@cf.port).to eq(4777)
  end

  it 'can configure docroot from file' do
    expect(@cf.docroot).to eq("./ui")
  end

  it 'can configure endpoint from file' do
    expect(@cf.endpoint).to eq("/catflap")
  end

  it 'can configure redir_protocol from file' do
    expect(@cf.redir_protocol).to eq("http")
  end

  it 'can configure redir_hostname from file' do
    expect(@cf.redir_hostname).to eq("json")
  end

  it 'can configure redir_port from file' do
    expect(@cf.redir_port).to eq(80)
  end

  it 'can configure fwplugin from file' do
    expect(@cf.fwplugin).to eq("iptables")
  end

  it 'can configure dports from file' do
    expect(@cf.dports).to eq("80,443")
  end
end
