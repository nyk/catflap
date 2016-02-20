Catflap
=======
![alt catflap](https://raw.githubusercontent.com/nyk/catflap/master/ui/images/catflap.png)

Catflap provides firewall level protection of multiple ports with a password
protected web gateway to allow developers and/or site demo/stage reviewers to
request entry after providing valid authentication credentials. Currently Catflap
supports Linux running the NetFilter (iptables) kernel-level firewall. However,
firewall specific implementations are provided as firewall plugin drivers and it
should be possible to write a separate plugin for the ipfw firewall on Mac OSX
and other FreeBSD derivatives.

Essentially, it is a more user-friendly form of "port knocking". The original
proof-of-concept implementation was run for almost three years by Demotix, to
protect development and staging servers from search engine crawlers and other
unwanted traffic.

# Use Cases
- Prevent web-bots and spiders from crawling and indexing your development,
  demo and staging servers. Since they are protected by a firewall there are no
  back doors.
- Provide a seamless login to sensitive web backends that may not have their own
  complete user authentication enabled. One example is Kibana, used as a part of
  the ELK logging service.
- Allow non-technical people to request access through a firewall when they do
  not have a static IP (e.g. from home office) and no access to a VPN.
- Provides simple to use "port knocking" that does not require any technical
  knowledge of command line networking from end users.

# Installation
Catflap is available as a ruby gem and can be installed with:

```
gem install catflap
```

You may also want to download the generic Linux init script
(https://github.com/nyk/catflap/blob/master/etc/init.d/catflap) and place that
in /etc/init.d/.

# Configuration
It is advisable to create a configuration file: /usr/local/etc/catflap.yaml
(this is the default location referenced by the init script, but you can specify
the location of your configuration file with the --config-file parameter to
the catflap command line tool.

This configuration file is a YAML file and the default configuration is listed
below:

```YAML
server:
  listen_addr: '0.0.0.0'          # What ip address the catflap server should listen on.
  port: 4777                      # The TCP port that the catflap server listens on.
  docroot: './ui'                 # You can override the ui location.
  endpoint: '/catflap'            # The endpoint for the REST API.
  passfile: './etc/passfile.yaml' # Pass phrases are stored here in this file.

firewall:
  plugin: 'netfilter'             # Options are netfilter or iptables.
  dports: '80,443'                # Lock multiple ports separating them by commas.
  options:                        # Options are specific to each firewall plugin driver.
    chain: 'CATFLAP'              # Two chains will be created <chain>-ALLOW & <chain>-DENY.
    log_rejected: true            # Enable logging of rejected requests.
    accept_local: true            # This is only set to false only when developers are testing catflap.
```

Once your configuration is in place you will then want to install the rules and
initialize catflap. This can be done with the command line tool:

```
sudo catflap -f /etc/catflap.yaml install
```

Catflap has a command line tool that you can use to add or remove addresses from
the access chain and other household maintenance. Just run 'catflap help' to see
the available options.

Now you will want to start the service. If you are using the init.d script this
is easy:

```
sudo service catflap start
```

If not you will need to start it with the command line directly (useful for
testing and debugging issues):
```
sudo catflap -f /etc/catflap.yaml start
```

# Gaining Access
Addresses and address ranges can be added using the command line with the 'add'
command, but remote users can request that their current IP address be granted
access by visiting the URL of the website that is being catflapped with their
web-browser. Catflap will redirect the target port (e.g. port 80) to the
Catflap port (e.g. 4777), so they will see the Catflap login screen. Once they
provide a valid pass phrase, their browser will refresh and they will see the
target website.

This is the default configuration, provided by the 'netfilter'
driver, which uses NAT on the firewall to forward the ports. You can use the
'ipfilter' driver instead, if you want to reject or drop packets rather than
automatically redirect to the Catflap login. The user would instead have to go
to the Catflap URL directly. However, the default 'netfilter' driver is
recommended if you want the best and most seamless end-user experience.

# Security considerations
Although we have been careful to avoid application level security vulnerabilities,
such as shell injection attacks, and no web user submitted data is passed to the
operating system without being sanitized (i.e. IP addresses are validated as being
valid IP addresses before being sent to the firewall interface), there are still
some areas of security concern to be aware of:
- The web service must run with root privileges, at the very least be run sudo
  as a user with root privileges to add rules to the firewall. Such privileges are
  unavoidable because the firewall runs in the kernel of the operating system.
  A future release will separate the firewall execution process from the web
  server, so the web server will run as an unprivileged user and only the
  'Executor' process will run with higher privileges on an internal TCP network.
- The pass phrases in the passfile.yaml file are not encrypted. This file should
  be placed in a private directory owned by root, chmod 600. If an unauthorized user
  can read that file, then you have larger security problems than Catflap :)
- Unless you use SSL encryption it is not easy, but possible, for a network sniffer to capture
  a valid token and possibly reuse the token to open the port for their own IP
  address. This risk is very much lessened by the use of timestamps to expire
  authentication tokens, but there is still some potential risk exposure. That
  risk is eliminated entirely by encrypting traffic with TLS/SSL.
- It is recommended to flush the Catflap access rules every day or so (e.g. using
  a cron job that calls 'sudo catflap purge' command). This is analogous to expiring
  user login sessions.
- If you want to revoke access on a particular pass phrase, you must remove the
  pass phrase from the passfile and ALSO flush the CATFLAP-ALLOW firewall chain, by
  using the 'catflap purge' command, or remove each IP address with the
  'catflap revoke <ip>' command.
