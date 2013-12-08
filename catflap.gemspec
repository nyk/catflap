Gem::Specification.new do |s|
  s.name        = 'catflap'
  s.version     = '0.0.2'
  s.summary     = 'Manage NetFilter-based rules to grant port access on-demand via commandline or REST API requests.'
  s.description = 'A simple solution to provide on-demand service access (e.g. port 80 on webserver), where a more robust and secure VPN solution is not available.'
  s.authors     = ['Nyk Cowham']
  s.email       = 'nyk@demotix.com'
  s.files 	= ['lib/catflap.rb', 'lib/catflap-http.rb', 'bin/catflap']
  s.executables = ['catflap']
  s.licenses	= ['MIT']
  s.requirements = 'NetFilters (iptables) installed and working.'
  s.homepage	= 'https://github.com/nyk/catflap'
end
