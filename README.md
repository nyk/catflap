catflap
=======

Creates a web accessible "cat flap" to open specific port connection to a web server by pinging a particular port. Catflap currently supports firewall rules using NetFilter (iptables) which is included as standard on most Linux distributions. It should work for Mac OS X systems, but only if iptables is installed with macports, etc. The intention is to add support for ipfw (native firewall for Mac OS X) in the very near future as a plugin. Currently there is no direct support for Microsoft Windows, other than those using cygwin or other Unix subshell installations. Further native support for Microsoft Windows is not planned by the author, but the plugin system for supporting ipfw/OSX could potentially be used by another developer who wishes to support a Windows plugin.

# Installation
Catflap is available as a ruby gem and can be installed with:

```
gem install catflap --pre
```

You may want to download the generic Linux init script (https://github.com/nyk/catflap/blob/master/etc/init.d/catflap) and place that in /etc/init.d/.

# Configuration
It is advisable to create a configuration file: /usr/local/etc/catflap.yaml (this is the default location referenced by the init script, but an be changed by passing the --config-file parameter to catflap.

This configuration file is a YAML file:

```YAML
server:
  port: 4777

rules:
  chain: 'catflap-accept'
  dports: '80,8080,443'
```

The default listening port is 4777, but you are strongly urged to change this to something different. The rules chain is the name of the user-defined chain that iptables will be configured with to contain all the catflap firewall rules.

The dports parameter tells catflap which ports should be blocked and guarded by catflap. By default, these are the common web port, 80 and 443. However, you can block other service ports such as SSH port 22 (be VERY careful how you do something like that!!) or an ftp port. Mutliple ports must be a string separated by commas with no spaces.

Once your configuration is in place you will then want to install the rules and initialize catflap. This can be done with the command line:

```
catflap -f /usr/local/etc/catflap.yaml --install
```

Catflap has a command line tool that you can use to add or remove addresses from the access chain and other household maintenance. Just run 'catflap -h' to see the options.

Now you will want to start the service. If you are using the init.d script this is easy:

```
sudo service catflap start
```

If not you will need to start it with the commandline directly (useful for testing and debugging issues):
```
sudo catflap -f /usr/local/etc/catflap.yaml --start-server
```

# Gaining Access
Addresses and address ranges can be added by the commandline using the '--add' option, but remote users can request that their current IP address be granted access by visiting the URL of the catflap service with their web-browser: http://<url>:4777/enter

# Security
Catflap is very low security! Anyone with the port and IP for your catflap service can gain full access to your protected ports. The main use case for catflap is to completely hide development, staging and test sites from crawlers, indexers and random access from outside, but to provide a convenient way for developers and other staff to open access on-demand without asking an admin to grant access. DO NOT rely on catflap to protect sensitive information or access to services that could be exploited! The roadmap (which exists in my head) does have improved security high on the list. Catflap lays in the 'convenience' end of the convenience vs. security trade-off spectrum.
