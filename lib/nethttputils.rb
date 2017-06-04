require "net/http"
require "openssl"

require "logger"


module NetHTTPUtils

  class << self
    attr_accessor :logger
  end
  self.logger = Logger.new STDOUT
  self.logger.level = ENV["LOGLEVEL_#{name}"] ? Logger.const_get(ENV["LOGLEVEL_#{name}"]) : Logger::WARN
  self.logger.formatter = lambda do |severity, datetime, progname, msg|
    "#{severity.to_s[0]} #{datetime.strftime "%y%m%d %H%M%S"} : #{name} : #{msg}\n"
  end

  class Error < RuntimeError
    attr_reader :code
    def initialize code, body
      @code = code
      super "NetHTTPUtils error ##{code} #{body}"
    end
  end

  class << self

    # private?
    def get_response url, mtd = :GET, type = :form, form: {}, header: [], auth: nil, timeout: 30, patch_request: nil, &block
      # form = Hash[form.map{ |k, v| [k.to_s, v] }]
      uri = URI.parse url
      mtd = mtd.upcase
      cookies = {}
      prepare_request = lambda do |uri|
        case mtd.upcase
          when :GET    ; Net::HTTP::Get
          when :POST   ; Net::HTTP::Post
          when :PUT    ; Net::HTTP::Put
          when :DELETE ; Net::HTTP::Delete
          when :PATCH  ; Net::HTTP::Patch
          else         ; raise "unknown method '#{mtd}'"
        end.new(uri).tap do |request| # somehow Get eats even raw url, not URI object
          patch_request.call uri, form, request if patch_request
          request.basic_auth *auth if auth
          request["cookie"] = [*request["cookie"], cookies.map{ |k, v| "#{k}=#{v}" }].join "; " unless cookies.empty?

          request.set_form_data form unless form.empty?
          if mtd == :POST || mtd == :PATCH
            request["Content-Type"] = case type
              when :form ; "application/x-www-form-urlencoded"
              when :json ; request.body = JSON.dump form     # yes this overwrites form data set few lines higher
                           "application/json"
              else       ; raise "unknown content-type '#{type}'"
            end
          end
          header.each{ |k, v| request[k.to_s] = v }

          logger.info request.path
          next unless logger.debug?
          logger.debug "header: #{request.each_header.to_a.to_s}"
          logger.debug "body: #{request.body.inspect.tap{ |body| body[100..-1] = "..." if body.size > 100 }}"
          stack = caller.reverse.map do |level|
            /((?:[^\/:]+\/)?[^\/:]+):([^:]+)/.match(level).captures
          end.chunk(&:first).map do |file, group|
            "#{file}:#{group.map(&:last).chunk{|_|_}.map(&:first).join(",")}"
          end
          logger.debug stack.join " -> "
          logger.debug request
        end
      end
      request = prepare_request[uri]
      start_http = lambda do |uri|
        begin
          Net::HTTP.start(
            uri.host, uri.port,
            use_ssl: uri.scheme == "https",
            verify_mode: OpenSSL::SSL::VERIFY_NONE,
            # read_timeout: 5,
          ).tap do |http|
            http.read_timeout = timeout #if timeout
            http.open_timeout = timeout #if timeout
            http.set_debug_output STDERR if logger.level == Logger::DEBUG # use `logger.debug?`?
          end
        rescue Errno::ECONNREFUSED => e
          e.message.concat " to #{uri}" # puts "#{e} to #{uri}"
          raise e
        rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNRESET, SocketError, OpenSSL::SSL::SSLError => e
          logger.warn "retrying in 5 seconds because of #{e.class}: #{e.message}"
          sleep 5
          retry
        rescue Errno::ETIMEDOUT
          logger.warn "ETIMEDOUT, retrying in 5 minutes"
          sleep 300
          retry
        end
      end
      http = start_http[uri]
      do_request = lambda do |request|
        response = begin
          http.request request, &block
        rescue Errno::ECONNRESET, Errno::ECONNREFUSED, Net::ReadTimeout, Net::OpenTimeout, Zlib::BufError, OpenSSL::SSL::SSLError => e
          logger.error "retrying in 30 seconds because of #{e.class} at: #{request.uri}"
          sleep 30
          retry
        end
        response.instance_variable_set "@nethttputils_close", http.method(:finish)
        # response.singleton_class.instance_eval{ attr_accessor :nethttputils_socket_to_close }
        response.to_hash.fetch("set-cookie", []).each{ |c| k, v = c.split(?=); cookies[k] = v[/[^;]+/] }
        case response.code
        when /\A3\d\d\z/
          logger.info "redirect: #{response["location"]}"
          new_uri = URI.join(request.uri, response["location"])
          new_host = new_uri.host
          if http.address != new_host ||
             http.port != new_uri.port ||
             http.use_ssl? != (new_uri.scheme == "https")
            logger.debug "changing host from '#{http.address}' to '#{new_host}'"
            http.finish
            http = start_http[new_uri]
          end
          do_request.call prepare_request[new_uri]
        when "404"
          logger.error "404 at #{request.method} #{request.uri} with body: #{
            response.body.is_a?(Net::ReadAdapter) ? "impossible to reread Net::ReadAdapter -- check the IO you've used in block form" : response.body.tap do |body|
              body.replace body.strip.gsub(/<script>.*?<\/script>/m, "").gsub(/<[^>]*>/, "") if body[/<html[> ]/]
            end.inspect
          }"
          response
        when "429"
          logger.error "429 at #{request.method} #{request.uri} with body: #{response.body.inspect}"
          response
        when /\A50\d\z/
          logger.error "#{response.code} at #{request.method} #{request.uri} with body: #{response.body.inspect}"
          response
        when /\A20/
          response
        else
          logger.info "code #{response.code} at #{request.method} #{request.uri}#{
            " and so #{url}" if request.uri.to_s != url
          } from #{
            [__FILE__, caller.map{ |i| i[/(?<=:)\d+/] }].join ?:
          }"
          logger.debug "header: #{response.to_hash}"
          logger.debug "body: #{
            response.body.tap do |body|
              body.replace body.strip.gsub(/<script>.*?<\/script>/m, "").gsub(/<[^>]*>/, "") if body[/<html[> ]/]
            end.inspect
          }"
          response
        end
      end
      do_request[request].tap do |response|
        cookies.each{ |k, v| response.add_field "Set-Cookie", "#{k}=#{v};" }
        logger.debug response.to_hash
      end
    end

    def request_data *args
      response = get_response *args
      raise Error.new response.code.to_i, response.body if %w{ 404 429 500 }.include? response.code
      response.body
    ensure
      response.instance_variable_get("@nethttputils_close").call if response
    end

  end
end


if $0 == __FILE__
  print "self testing... "

  fail unless NetHTTPUtils.request_data("http://httpstat.us/200") == "200 OK"
  fail unless NetHTTPUtils.get_response("http://httpstat.us/404").body == "404 Not Found"
  [404, 500].each do |code|
    begin
      fail NetHTTPUtils.request_data "http://httpstat.us/#{code}"
    rescue NetHTTPUtils::Error => e
      raise if e.code != code
    end
  end
  fail unless NetHTTPUtils.request_data("http://httpstat.us/400") == "400 Bad Request"
  fail unless NetHTTPUtils.get_response("http://httpstat.us/500").body == "500 Internal Server Error"

  puts "OK #{__FILE__}"
end
