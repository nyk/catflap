require 'catflap'
require 'webrick'
require 'json'
include WEBrick

##
# Module to implement a WEBrick web server.
#
# @author Nyk Cowham <nykcowham@gmail.com>
module CfWebserver
  # Add a mime type for *.rhtml files
  HTTPUtils::DefaultMimeTypes.store('rhtml', 'text/html')

  # Factory method to generate a new WEBrick server.
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @param [Boolean] https set to true to generate an HTTPS server.
  # @return void
  def generate_server(cf, https = false)
    port = (https == true) ? cf.https['port'] : cf.port

    # Expand relative paths - particularly important for daemonizing.
    docroot = File.expand_path cf.docroot

    config = {
      BindAddress: cf.listen_addr,
      Port: port,
      DocumentRoot: docroot,
      StartCallback: lambda do
        # Write the pid to file when the server starts.
        if File.writable? cf.pid_path
          File.open(get_pidfile(cf, https), 'w') do |file|
            file.puts Process.pid.to_s
          end
        end
      end,
      StopCallback: lambda do
        # Delete the pid file when the server shuts down.
        pidfile = get_pidfile(cf, https)
        File.delete pidfile if File.exist? pidfile
      end
    }

    config[:ServerType] = Daemon if cf.daemonize

    if https
      require 'webrick/https'
      require 'openssl'

      if File.readable? cf.https['certificate']
        cert = OpenSSL::X509::Certificate.new File.read cf.https['certificate']
      end

      if File.readable? cf.https['private_key']
        pkey = OpenSSL::PKey::RSA.new File.read cf.https['private_key']
      end

      config[:SSLEnable] = true

      if cert && pkey
        config[:SSLCertificate] = cert
        config[:SSLPrivateKey] = pkey
      else
        # We don't have a certificate so generate a new self-signed certificate.
        config[:SSLCertName] = [%w(CN localhost)]
      end

    end

    server = HTTPServer.new(config)
    yield server if block_given?

    %w(INT TERM).each do |signal|
      trap(signal) { server.shutdown }
    end

    server.start
  end

  # Method to start the WEBrick web server.
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @param [Boolean] https set to true to start an HTTPS server.
  # @return void
  def server_start(cf, https = false)
    generate_server(cf, https) do |server|
      server.mount cf.endpoint, CfApiServlet, cf

      # Redirect HTTP to HTTPS if force option is set.
      if !https && cf.https['force']
        server.mount_proc '/' do |req, res|
          res.set_redirect WEBrick::HTTPStatus::TemporaryRedirect,
                           'https://' + req.server_name
        end
      end
    end
  end

  # Method to stop the WEBrick web server.
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @param [Boolean] https set to true to stop an HTTPS server.
  # @return [Boolean] true if process termination was successful.
  def server_stop(cf, https = false)
    pid = get_pid(cf, https)
    Process.kill('INT', pid) if pid > 0
  end

  # Method to get the status of the WEBrick web server and process id.
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @param [Boolean] https set to true to get status of an HTTPS server.
  # @return [Hash<Sym, Object>] the process id or 0 if there is no pid.
  def server_status(cf, https = false)
    {
      pid: get_pid(cf, https),
      address: cf.listen_addr,
      port: https ? cf.https['port'] : cf.port
    }
  end

  # Method to get the process id of the running process.
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @param [Boolean] https set to true to get process id of an HTTPS server.
  # @return [Integer] the process id or 0 if there is no pid.
  def get_pid(cf, https = false)
    pidfile = get_pidfile(cf, https)
    pid = nil
    if File.readable? pidfile
      File.open(pidfile, 'r') do |file|
        pid = file.readline
      end
    end
    pid.to_i
  end

  # Method to get the pid file path
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @param [Boolean] https set to true to get pidfile of an HTTPS server.
  # @return [String] the file path to the pid file.
  def get_pidfile(cf, https = false)
    filename = https ? 'catflap-https.pid' : 'catflap-http.pid'
    cf.pid_path + File::SEPARATOR + filename
  end

  ##
  # A WEBrick servlet class to handle API requrests
  # @author Nyk Cowham <nykcowham@gmail.com>
  class CfApiServlet < HTTPServlet::AbstractServlet
    # Initializer to construct a new CfApiServlet object.
    # @param [HTTPServer] server a WEBrick HTTP server object.
    # @param [Catflap] cf a fully instantiated Catflap object.
    # @return void
    def initialize(server, cf)
      super server
      @cf = cf
    end

    # Implementation of HTTPServlet::AbstractServlet method to handle GET
    # method requests.
    # @param [HTTPRequest] req a WEBrick::HTTPRequest object.
    # @param [HTTPResponse] resp a WEBrick::HTTPResponse object.
    # @return void
    # rubocop:disable Style/MethodName
    def do_POST(req, resp)
      # Split the path into piece
      path = req.path[1..-1].split('/')

      # We don't want to cache catflap login page so set response headers.
      resp['Cache-Control'] = 'no-cache, no-store, must-revalidate'
      resp['Pragma'] = 'no-cache'
      resp['Expires'] = '0'

      response_class = CfRestService.const_get 'CfRestService'

      raise "#{response_class} not a Class" unless response_class.is_a?(Class)

      raise raise HTTPStatus::NotFound unless path[1]

      response_method = path[1].to_sym
      # Make sure the method exists in the class
      raise HTTPStatus::NotFound unless response_class
                                        .respond_to? response_method

      if :sync == response_method
        resp.body = response_class.send response_method, req, resp, @cf
      end

      if :knock == response_method
        resp.body = response_class.send response_method, req, resp, @cf
      end

      # Remaining path segments get passed in as arguments to the method
      if path.length > 2
        resp.body = response_class.send response_method, req, resp,
                                        @cf, path[1..-1]
      else
        resp.body = response_class.send response_method, req, resp, @cf
      end
      raise HTTPStatus::OK
    end
  end
end
# rubocop:enable Style/MethodName

##
# REST service to handle REST requests from CfApiServlet.
# @author Nyk Cowham <nykcowham@gmail.com>
module CfRestService
  # REST service handler Class
  class CfRestService
    # Numeric response code indicating that the token has expired.
    STATUS_TOKEN_EXPIRED = 405
    # Numeric response code indicating that the handshake was ok.
    STATUS_SYNC_OK = 200
    # Numeric response code indicating a failed authentication attempt.
    STATUS_AUTH_FAIL = 401
    # Numeric response code indicating a successful authentication attempt.
    STATUS_AUTH_PASS = 200

    # Handler method for handling sync/timestamp requests for handshaking.
    #
    # This is a handshake request from the browser for a timestamp to use
    # to encrypt the pass phrase. This timestamp is passed back along with
    # pass phrase. If the timestamp is older than the expiry then the token
    # will be rejected. If the timestamp has not expired it will be used to
    # generate a matching token for authentication.
    # @return [Integer] an integer representation of a unix timestamp.

    def self.sync(_req, _res, _cf)
      result = {
        Status: 'Handshake sync OK',
        StatusCode: STATUS_SYNC_OK,
        Timestamp: Time.new.to_i
      }
      JSON.generate(result)
    end

    # Handler method for handling knock requests for authentication.
    # @param [WEBRick::HTTPRequest] req a WEBrick request object.
    # @param [WEBrick::HTTPResponse] resp a WEBrick response object.
    # @param [Catflap] cf a fully instantiated Catflap object.
    # @return void

    def self.knock(req, _resp, cf)
      ip = req.peeraddr.pop
      query = req.query
      passkey = query['_key']

      # Calculate difference between the timestamp sent to the client and
      # the current timestamp.
      ts_delta = Time.new.to_i - query['ts'].to_i

      if ts_delta > cf.token_ttl
        result = {
          Status: 'Expired Token',
          StatusCode: STATUS_TOKEN_EXPIRED
        }
        JSON.generate(result)
      end

      # If we have a matching key in the passfile then create a test token.
      unless cf.passphrases[query['_key']].nil?
        test_token = cf.generate_token(cf.passphrases[passkey], query['ts'])
      end

      # by default we tell the browser to reload the page, but we can configure
      # catflap in the configuration file to redirect to some other URL.
      redirect_url = cf.redirect_url ? cf.redirect_url : 'reload'

      if test_token && test_token == query['token']
        # The tokens matched and validated so we add the address and respond
        # to the browser.
        cf.firewall.add_address ip unless cf.firewall.check_address(ip)

        result = {
          Status: 'Authenticated',
          StatusCode: STATUS_AUTH_PASS,
          RedirectUrl: redirect_url
        }

      else
        result = {
          Status: 'Authentication failed',
          StatusCode: STATUS_AUTH_FAIL
        }
      end
      JSON.generate(result)
    end
  end
end
