# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'catflap/version'

Gem::Specification.new do |s|
  s.name        = 'catflap'
  s.version     = Catflap::VERSION
  s.summary     = 'Manage NetFilter-based rules to grant port access on-demand via commandline or REST API requests.'
  s.description = 'A simple solution to provide on-demand service access (e.g. port 80 on webserver), where a more robust and secure VPN solution is not available.'
  s.authors     = ['Nyk Cowham']
  s.email       = 'nykcowham@gmail.com'
  s.homepage	= 'https://github.com/nyk/catflap'
  s.files 	= `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|tasks|features)/}) }
  s.executables = ['catflap']
  s.licenses	= ['MIT']
  s.requirements = 'NetFilters (iptables) installed and working.'
  s.require_paths = ["lib"]
  s.add_dependency 'json', '>= 1.8.3'
  s.add_development_dependency "bundler", "~> 1.11"
  s.add_development_dependency "rake", "~> 10.0"
  s.add_development_dependency "rspec", "~> 3.0"
  s.bindir = 'bin'
end
