#!/usr/bin/env ruby

require 'catflap'
require 'webrick'
include WEBrick

module CatflapWebserver

  def self.generate_server(port)
    config = {:Port => port}
    server = HTTPServer.new(config)
    yield server if block_given?
    ['INT', 'TERM'].each {|signal| 
      trap(signal) {server.shutdown}
    }
    server.start
  end

  def self.start_server(port = 4777)
    generate_server(port) do |server|
      server.mount('/', Servlet)
    end
  end

  class Servlet < HTTPServlet::AbstractServlet
    def do_GET(req,resp)
      # Split the path into piece
      path = req.path[1..-1].split('/')
      raise HTTPStatus::OK if path[0] == 'favicon.ico'
      response_class = CatflapRestService.const_get("Service")
       
      if response_class and response_class.is_a?(Class)
        # There was a method given
        if path[0]
          response_method = path[0].to_sym
          # Make sure the method exists in the class
          raise HTTPStatus::NotFound if !response_class.respond_to?(response_method)

          if path[0] == "enter"
            url = response_class.send(response_method, req, resp)
            resp.set_redirect(HTTPStatus::Redirect, url)
          end

          # Remaining path segments get passed in as arguments to the method
          if path.length > 1
            resp.body = response_class.send(response_method, req, resp, path[1..-1])
          else
            resp.body = response_class.send(response_method, req, resp)
          end
          raise HTTPStatus::OK

        # No method was given, so check for an "index" method instead
        else
          raise HTTPStatus::NotFound if !response_class.respond_to?(:index)
          resp.body = response_class.send(:index)
          raise HTTPStatus::OK
        end
      else
        raise HTTPStatus::NotFound
      end
    end
  end
end

module CatflapRestService
  class Service

    @@cf = Catflap.new
    @@cf.dports = '80,8080,443'

    def self.index()
      return "hello world"
    end
 
    def self.enter(req, resp)
      ip = req.peeraddr.pop
      host = req.addr[2]
      @@cf.add_address!(ip) unless @@cf.check_address(ip)
      return "http://" << host << ":80"
    end

    def self.add(req, resp, args)
      ip = args[0]
      unless @@cf.check_address(ip)
        @@cf.add_address!(ip)
        return "#{ip} has been granted access"
      else
        return "#{ip} already has access"
      end
    end

    def self.remove(req, resp, args)
      ip = args[0]
      @@cf.delete_address!(ip)
      return "Access granted to #{ip} has been removed"
    end

    def self.check(req, resp, args)
      ip = args[0]
      
      if @@cf.check_address(ip)
        return "#{ip} has access to ports: #{@@cf.dports}"
      else
        return "#{ip} does not have access to ports: #{@@cf.dports}"
      end
    end
  end
end
