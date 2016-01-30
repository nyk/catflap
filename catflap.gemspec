Gem::Specification.new do |s|
  s.name        = 'catflap'
  s.version     = '1.0.0'
  s.summary     = 'Manage NetFilter-based rules to grant port access on-demand via commandline or REST API requests.'
  s.description = 'A simple solution to provide on-demand service access (e.g. port 80 on webserver), where a more robust and secure VPN solution is not available.'
  s.authors     = ['Nyk Cowham']
  s.email       = 'nykcowham@gmail.com'
  s.files 	= ['lib/catflap.rb', 'lib/catflap-http.rb', 'bin/catflap', 'lib/plugins/firewall/iptables.rb']
  s.executables = ['catflap']
  s.licenses	= ['MIT']
  s.requirements = 'NetFilters (iptables) installed and working.'
  s.homepage	= 'https://github.com/nyk/catflap'
end
