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

    def do_POST req, resp
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

          if :sync == response_method
            resp.body = response_class.send response_method, req, resp, @cf
          end

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

    # Numeric response code indicating that the token has expired.
    STATUS_TOKEN_EXPIRED = 405;
    # Numeric response code indicating that the handshake was ok.
    STATUS_SYNC_OK = 200;
    # Numeric response code indicating a failed authentication attempt.
    STATUS_AUTH_FAIL = 401;
    # Numeric response code indicating a successful authentication attempt.
    STATUS_AUTH_PASS = 200;

    # Handler method for handling sync/timestamp requests for handshaking.
    #
    # This is a handshake request from the browser for a timestamp to use
    # to encrypt the pass phrase. This timestamp is passed back along with the
    # pass phrase. If the timestamp is older than the expiry then the token
    # will be rejected. If the timestamp has not expired it will be used to
    # generate a matching token for authentication.
    # @return [Integer] an integer representation of a unix timestamp.

    def self.sync req, resp, cf
      result = {
        :Status => "Handshake sync OK",
        :StatusCode => STATUS_SYNC_OK,
        :Timestamp => Time.new.to_i
      }
      return JSON.generate(result)
    end

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

      # Calculate difference between the timestamp sent to the client and
      # the current timestamp.
      ts_delta = Time.new.to_i - query['ts'].to_i

      if ts_delta > cf.token_ttl
        result = {
          :Status => "Expired Token",
          :StatusCode => STATUS_TOKEN_EXPIRED
        }
        return JSON.generate(result)
      end

      # If we have a matching key in the passfile then create a test token.
      if cf.passphrases[query['_key']] != nil
        test_token = cf.generate_token(cf.passphrases[passkey], query['ts'])
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
          :StatusCode => STATUS_AUTH_PASS,
          :RedirectUrl => redirect_url
        }

      else
        result = {
          :Status => "Authentication failed",
          :StatusCode => STATUS_AUTH_FAIL,
        }
      end
      return JSON.generate(result);
    end

  end
end
