require 'catflap'
require 'webrick'
require 'json'
include WEBrick

module CfWebserver
  # Add a mime type for *.rhtml files
  HTTPUtils::DefaultMimeTypes.store('rhtml', 'text/html')

  def generate_server bind_addr, port
    config = {:BindAddress => bind_addr, :Port => port}
    server = HTTPServer.new(config)
    yield server if block_given?
    ['INT', 'TERM'].each {|signal|
      trap(signal) {server.shutdown}
    }
    server.start
  end

  def server_start cf
    generate_server(cf.bind_addr, cf.port) do |server|
      server.mount '/catflap', CfApiServlet, cf
      server.mount '/', HTTPServlet::FileHandler, cf.docroot
    end
  end

  class CfApiServlet < HTTPServlet::AbstractServlet

    def initialize server, cf
      super server
      @cf = cf
    end

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

module CfRestService
  class CfRestService

    AUTH_FAIL_CODE = 401;
    AUTH_PASS_CODE = 200;

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
        cf.firewall.add_address! ip
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
  end
end
