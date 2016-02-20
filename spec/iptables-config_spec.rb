require 'spec_helper'

config_path = 'spec/config-files/iptables.yaml'

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

  it 'can configure redirect_url from file' do
    expect(@cf.redirect_url).to eq("http://localhost/")
  end

  it 'can configure fwplugin from file' do
    expect(@cf.fwplugin).to eq("iptables")
  end

  it 'can configure dports from file' do
    expect(@cf.dports).to eq("80,443")
  end
end
