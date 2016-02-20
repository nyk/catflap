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
  # @param [String] bind_addr the IP address to listen on (e.g. 0.0.0.0).
  # @param [String] port the port to listen on (e.g. 4777).
  # @return void

  def generate_server bind_addr, port
    config = {:BindAddress => bind_addr, :Port => port}
    server = HTTPServer.new(config)
    yield server if block_given?
    ['INT', 'TERM'].each {|signal|
      trap(signal) {server.shutdown}
    }
    server.start
  end

  # Method to start the WEBrick web server.
  # @param [Catflap] cf a fully instantiated Catflap object.
  # @return void

  def server_start cf
    generate_server(cf.bind_addr, cf.port) do |server|
      server.mount '/catflap', CfApiServlet, cf
      server.mount '/', HTTPServlet::FileHandler, cf.docroot
    end
  end

  ##
  # A WEBrick servlet class to handle API requrests
  # @author Nyk Cowham <nykcowham@gmail.com>

  class CfApiServlet < HTTPServlet::AbstractServlet

    # Initializer to construct a new CfApiServlet object.
    # @param [HTTPServer] server a WEBrick HTTP server object.
    # @param [Catflap] cf a fully instantiated Catflap object.
    # @return void

    def initialize server, cf
      super server
      @cf = cf
    end

    # Implementation of HTTPServlet::AbstractServlet method to handle GET method
    # requests.
    # @param [HTTPRequest] req a WEBrick::HTTPRequest object.
    # @param [HTTPResponse] resp a WEBrick::HTTPResponse object.
    # @return void

    def do_GET req, resp
      # Split the path into piece
      path = req.path[1..-1].split('/')

      # We don't want to cache catflap login page so set response headers.
      resp['Cache-Control'] = "no-cache, no-store, must-revalidate"
      resp['Pragma'] = "no-cache"
      resp['Expires'] = "0"

      response_class = CfRestService.const_get 'CfRestService'

      if response_class and response_class.is_a? Class

        # There was a method given
        if path[1]
          response_method = path[1].to_sym
          # Make sure the method exists in the class
          raise HTTPStatus::NotFound if !response_class.respond_to? response_method

          if :knock == response_method
            resp.body = response_class.send response_method, req, resp, @cf
          end

          # Remaining path segments get passed in as arguments to the method
          if path.length > 2
            resp.body = response_class.send response_method, req, resp, @cf, path[1..-1]
          else
            resp.body = response_class.send response_method, req, resp, @cf
          end
          raise HTTPStatus::OK

        # No method was given, so check for an "index" method instead
        else
          raise HTTPStatus::NotFound if !response_class.respond_to? :index
          resp.body = response_class.send :index
          raise HTTPStatus::OK
        end
      else
        raise HTTPStatus::NotFound
      end
    end
  end
end

##
# REST service to handle REST requests from CfApiServlet.
# @author Nyk Cowham <nykcowham@gmail.com>

module CfRestService

  # REST service handler Class

  class CfRestService

    # Numeric response code indicating a failed authentication attempt.
    AUTH_FAIL_CODE = 401;
    # Numeric response code indicating a successful authentication attempt.
    AUTH_PASS_CODE = 200;

    # Handler method for handling knock requests for authentication.
    # @param [WEBRick::HTTPRequest] req a WEBrick request object.
    # @param [WEBrick::HTTPResponse] resp a WEBrick response object.
    # @param [Catflap] cf a fully instantiated Catflap object.
    # @return void

    def self.knock req, resp, cf
      authenticated = false
      ip = req.peeraddr.pop
      query = req.query()
      passkey = query['_key']

      # If we have a matching key in the passfile then create a test token.
      if cf.passphrases[query['_key']] != nil
        test_token = cf.generate_token(cf.passphrases[passkey], query['random'])
      end

      # by default we tell the browser to reload the page, but we can configure
      # catflap in the configuration file to redirect to some other URL.
      redirect_url = (cf.redirect_url) ? cf.redirect_url : "reload"

      if test_token and test_token == query['token']
        # The tokens matched and validated so we add the address and respond
        # to the browser.
        if not cf.firewall.check_address ip
          cf.firewall.add_address! ip
        end

        result = {
          :Status => "Authenticated",
          :StatusCode => AUTH_PASS_CODE,
          :RedirectUrl => redirect_url
        }

      else
        result = {
          :Status => "Authentication failed",
          :StatusCode => AUTH_FAIL_CODE,
        }
      end
      return JSON.generate(result);
    end
=begin
    NOT RELEASING WEBAPI CODE UNTIL WE HAVE ADMIN PASSWORD PROTECTION
    def self.add req, resp, cf, args
      ip = args[0]
      unless cf.check_address ip
        cf.add_address! ip
        return "#{ip} has been granted access"
      else
        return "#{ip} already has access"
      end
    end

    def self.remove req, resp, cf, args
      ip = args[0]
      cf.delete_address! ip
      return "Access granted to #{ip} has been revoked"
    end

    def self.check req, resp, cf, args
      ip = args[0]

      if cf.check_address ip
        return "#{ip} has access to ports: #{cf.dports}"
      else
        return "#{ip} does not have access to ports: #{cf.dports}"
      end
    end
=end
  end
end
