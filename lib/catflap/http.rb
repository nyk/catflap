require 'catflap'
require 'webrick'
require 'json'
include WEBrick

module CfWebserver
  # Add a mime type for *.rhtml files
  HTTPUtils::DefaultMimeTypes.store('rhtml', 'text/html')

  def self.generate_server port
    config = {:Port => port}
    server = HTTPServer.new(config)
    yield server if block_given?
    ['INT', 'TERM'].each {|signal|
      trap(signal) {server.shutdown}
    }
    server.start
  end

  def self.start_server cf
    generate_server cf.port do |server|
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

      response_class = CfRestService.const_get 'CfRestService'

      if response_class and response_class.is_a? Class

        # There was a method given
        if path[1]
          response_method = path[1].to_sym
          # Make sure the method exists in the class
          raise HTTPStatus::NotFound if !response_class.respond_to? response_method

          if :knock == response_method
            url = response_class.send response_method, req, resp, @cf
            #resp.set_redirect HTTPStatus::Redirect, url
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

    def self.index
      return "hello world"
    end

    def self.knock req, resp, cf
      ip = req.peeraddr.pop
      host = req.addr[2]
      query = req.query();
      if query['token'] == cf.generate_token(cf.passphrase, query['random'])
        result = {
          :host => host,
          :ip => ip
        }
        return JSON.generate(result);
      end
      #cf.add_address! ip unless cf.check_address ip
      #return "http://" << host << ":80"
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
      return "Access granted to #{ip} has been removed"
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
