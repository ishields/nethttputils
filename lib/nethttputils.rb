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
    def initialize body, code = nil
      @code = code
      super "HTTP error ##{code} #{body}"
    end
  end

  class << self

    def remove_tags str
      str.gsub(/<script( type="text\/javascript"| src="[^"]+")?>.*?<\/script>/m, "").gsub(/<[^>]*>/, "").strip
    end

    # TODO: make it private?
    def get_response url, mtd = :GET, type = :form, form: {}, header: {}, auth: nil, timeout: 30, max_timeout_retry_delay: 3600, max_sslerror_retry_delay: 3600, max_read_retry_delay: 3600, max_econnrefused_retry_delay: 3600, max_socketerror_retry_delay: 3600, patch_request: nil, &block
      uri = URI.parse begin
        URI url
        url
      rescue URI::InvalidURIError
        URI.escape url
      end unless uri.is_a? URI::HTTP


      logger.warn "Warning: query params included in `url` argument are discarded because `:form` isn't empty" if uri.query && !form.empty?
      # we can't just merge because URI fails to parse such queries as "/?1"

      uri.query = URI.encode_www_form form if :GET == (mtd = mtd.upcase) && !form.empty?
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
          # pp Object.instance_method(:method).bind(request).call(:set_form).source_location
          if (mtd == :POST || mtd == :PATCH) && !form.empty?
            case type
              when :json ; request.body = JSON.dump form
                           request.content_type = "application/json"
              when :form ; if form.any?{ |k, v| v.respond_to? :to_path }
                             request.set_form form, "multipart/form-data"
                           else
                             request.set_form_data form
                             request.content_type = "application/x-www-form-urlencoded;charset=UTF-8"
                           end
              else       ; raise "unknown content-type '#{type}'"
            end
          end
          header.each{ |k, v| request[k.to_s] = v }

          logger.info "> #{request.class} #{uri.host} #{request.path}"
          next unless logger.debug?
          logger.debug "content-type: #{request.content_type}" unless mtd == :GET
          curl_form = case request.content_type
            when "application/json" ; "-d #{JSON.dump form} "
            when "multipart/form-data" ; form.map{ |k, v| "-F \"#{k}=#{v.respond_to?(:to_path) ? "@#{v.to_path}" : v}\" " }.join
            when "application/x-www-form-urlencoded" ; "-d \"#{URI.encode_www_form form}\" "
            else ; mtd == :GET ? "" : fail("unknown content-type '#{request.content_type}'")
          end
          logger.debug "curl -vsSL -o /dev/null #{
            request.each_header.map{ |k, v| "-H \"#{k}: #{v}\" " unless k == "host" }.join
          }#{curl_form}#{url.gsub "&", "\\\\&"}"
          logger.debug "> header: #{request.each_header.to_a}"
          logger.debug "> body: #{request.body.inspect.tap{ |body| body[997..-1] = "..." if body.size > 500 }}"
          stack = caller.reverse.map do |level|
            /((?:[^\/:]+\/)?[^\/:]+):([^:]+)/.match(level).captures
          end.chunk(&:first).map do |file, group|
            "#{file}:#{group.map(&:last).chunk{|_|_}.map(&:first).join(",")}"
          end
          logger.debug stack.join " -> "
        end
      end
      start_http = lambda do |uri|
        delay = 5
        begin
          Net::HTTP.start(
            uri.host, uri.port,
            use_ssl: uri.scheme == "https",
            verify_mode: OpenSSL::SSL::VERIFY_NONE,
            **({open_timeout: timeout}), #  if timeout
            **({read_timeout: timeout}), #  if timeout
          ) do |http|
            # http.open_timeout = timeout   # seems like when opening hangs, this line in unreachable
            # http.read_timeout = timeout
            http.set_debug_output( Object.new.tap do |obj|
              obj.instance_eval do
                def << msg
                  @@buffer ||= "[Net::HTTP debug] "
                  @@buffer.concat msg
                  @@buffer = @@buffer[0...997] + "..." if @@buffer.size > 500
                  return unless @@buffer.end_with? ?\n
                  NetHTTPUtils.logger.debug @@buffer.sub ?\n, "  "
                  @@buffer = nil
                end
              end
            end ) if logger.level == Logger::DEBUG # use `logger.debug?`?
            http
          end
        rescue Errno::ECONNREFUSED => e
          if max_econnrefused_retry_delay < delay *= 2
            e.message.concat " to #{uri}"
            raise
          end
          logger.warn "retrying in #{delay} seconds because of #{e.class} '#{e.message}'"
          sleep delay
          retry
        rescue Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNRESET => e
          logger.warn "retrying in 5 seconds because of #{e.class} '#{e.message}'"
          sleep 5
          retry
        rescue SocketError => e
          if max_socketerror_retry_delay < delay *= 2
            e.message.concat " to #{uri}"
            raise e
          end
          logger.warn "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{uri}"
          sleep delay
          retry
        rescue Errno::ETIMEDOUT, Net::OpenTimeout => e
          raise if max_timeout_retry_delay < delay *= 2
          logger.warn "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{uri}"
          sleep delay
          retry
        rescue OpenSSL::SSL::SSLError => e
          raise if max_sslerror_retry_delay < delay *= 2
          logger.error "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{uri}"
          sleep delay
          retry
        end
      end
      http = start_http[uri]
      do_request = lambda do |request|
        delay = 5
        response = begin
          http.request request, &block
        rescue Errno::ECONNREFUSED, Net::ReadTimeout, Net::OpenTimeout, Zlib::BufError, Errno::ECONNRESET, OpenSSL::SSL::SSLError => e
          raise if max_read_retry_delay < delay *= 2
          logger.error "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{request.uri}"
          sleep delay
          retry
        end
        # response.instance_variable_set "@nethttputils_close", http.method(:finish)
        # response.singleton_class.instance_eval{ attr_accessor :nethttputils_socket_to_close }

        if response.key? "x-ratelimit-userremaining"
          c = response.fetch("x-ratelimit-userremaining").to_i
          logger.debug "x-ratelimit-userremaining: #{c}"
          t = response.fetch("x-ratelimit-clientremaining").to_i
          logger.debug "x-ratelimit-clientremaining: #{t}"
          unless 100 < c
            a = response.fetch("x-timer")[/\d+/].to_i
            b = response.fetch("x-ratelimit-userreset").to_i
            t = (b - a + 1).fdiv c
            logger.warn "x-ratelimit sleep #{t} seconds"
            sleep t
          end
        end

        response.to_hash.fetch("set-cookie", []).each{ |c| k, v = c.split(?=); cookies[k] = v[/[^;]+/] }
        case response.code
        when /\A3\d\d\z/
          logger.info "redirect: #{response["location"]}"
          new_uri = URI.join request.uri, URI.escape(response["location"])
          new_host = new_uri.host
          if http.address != new_host ||
             http.port != new_uri.port ||
             http.use_ssl? != (new_uri.scheme == "https")
            logger.debug "changing host from '#{http.address}' to '#{new_host}'"
            # http.finish
            http = start_http[new_uri]
          end
          do_request.call prepare_request[new_uri]
        when "404"
          logger.error "404 at #{request.method} #{request.uri} with body: #{
            if response.body.is_a? Net::ReadAdapter
              "impossible to reread Net::ReadAdapter -- check the IO you've used in block form"
            elsif response.to_hash["content-type"] == ["image/png"]
              response.to_hash["content-type"].to_s
            else
              response.body.tap do |body|
                body.replace remove_tags body if body[/<html[> ]/]
              end.inspect
            end
          }"
          response
        when "429"
          logger.error "429 at #{request.method} #{request.uri} with body: #{response.body.inspect}"
          response
        when /\A50\d\z/
          logger.error "#{response.code} at #{request.method} #{request.uri} with body: #{
            response.body.tap do |body|
              body.replace remove_tags body if body[/<html[> ]/]
            end.inspect
          }"
          response
        when /\A20/
          response
        else
          logger.warn "code #{response.code} at #{request.method} #{request.uri}#{
            " and so #{url}" if request.uri.to_s != url
          } from #{
            [__FILE__, caller.map{ |i| i[/(?<=:)\d+/] }].join ?:
          }"
          logger.debug "< header: #{response.to_hash}"
          logger.debug "< body: #{
            response.body.tap do |body|
              body.replace remove_tags body if body[/<html[> ]/]
            end.inspect
          }"
          response
        end
      end
      do_request[prepare_request[uri]].tap do |response|
        cookies.each{ |k, v| response.add_field "Set-Cookie", "#{k}=#{v};" }
        logger.debug "< header: #{response.to_hash}"
      end
    end

    def request_data *args, &block
      response = get_response *args, &block
      raise Error.new(
        (response.to_hash["content-type"] == ["image/png"] ? response.to_hash["content-type"] : response.body),
        response.code.to_i
      ) unless response.code[/\A(20\d|3\d\d)\z/]
      if response["content-encoding"] == "gzip"
        Zlib::GzipReader.new(StringIO.new(response.body)).read
      else
        response.body
      end.tap do |string|
        string.instance_variable_set :@uri_path, response.uri.path
      end
    # ensure
    #   response.instance_variable_get("@nethttputils_close").call if response
    end

  end
end


if $0 == __FILE__
  STDOUT.sync = true
  print "self testing... "
  require "pp"

  require "webrick"
  require "json"
  server = WEBrick::HTTPServer.new Port: 8000
  server.mount_proc ?/ do |req, res|
    # pp req.dup.tap{ |_| _.instance_variable_set "@config", nil }
    # res.status = WEBrick::HTTPStatus::RC_ACCEPTED
    res.body = JSON.dump [req.unparsed_uri, req.header.keys]
  end
  Thread.abort_on_exception = true
  Thread.new{ server.start }
  fail unless JSON.dump(["/", %w{ accept-encoding accept user-agent host connection }]) == NetHTTPUtils.request_data("http://localhost:8000/")
  fail unless JSON.dump(["/?1", %w{ accept-encoding accept user-agent host connection }]) == NetHTTPUtils.request_data("http://localhost:8000/?1")
  fail unless JSON.dump(["/?1=2", %w{ accept-encoding accept user-agent host connection }]) == NetHTTPUtils.request_data("http://localhost:8000/?1=2")
  fail unless JSON.dump(["/?1=3", %w{ accept-encoding accept user-agent host connection }]) == NetHTTPUtils.request_data("http://localhost:8000/?1=2&3=4", form: {1=>3})
  fail unless JSON.dump(["/", %w{ accept-encoding accept user-agent host content-type connection content-length }]) == NetHTTPUtils.request_data("http://localhost:8000/", :post, form: {1=>2})
  server.shutdown

  fail unless NetHTTPUtils.request_data("http://httpstat.us/200") == "200 OK"
  [400, 404, 500, 503].each do |code|
    begin
      fail NetHTTPUtils.request_data "http://httpstat.us/#{code}"
    rescue NetHTTPUtils::Error => e
      raise unless e.code == code
    end
  end
  fail unless NetHTTPUtils.get_response("http://httpstat.us/400").body == "400 Bad Request"
  fail unless NetHTTPUtils.get_response("http://httpstat.us/404").body == "404 Not Found"
  fail unless NetHTTPUtils.get_response("http://httpstat.us/500").body == "500 Internal Server Error"
  fail unless NetHTTPUtils.get_response("http://httpstat.us/503").body == "503 Service Unavailable"
  NetHTTPUtils.logger.level = Logger::FATAL
  [
    ["https://imgur.com/a/cccccc"],
    ["https://imgur.com/mM4Dh7Z"],
    ["https://i.redd.it/si758zk7r5xz.jpg", "HTTP error #404 [\"image/png\"]"],
  ].each do |url, expectation|
    begin
      puts NetHTTPUtils.remove_tags NetHTTPUtils.request_data url
      fail
    rescue NetHTTPUtils::Error => e
      raise e.code.inspect unless e.code == 404
      raise e.to_s if e.to_s != expectation if expectation
    end
  end
  %w{
    http://minus.com/lkP3hgRJd9npi
    http://www.cutehalloweencostumeideas.org/wp-content/uploads/2017/10/Niagara-Falls_04.jpg
  }.each do |url|
    begin
      fail NetHTTPUtils.request_data url, max_socketerror_retry_delay: -1
    rescue SocketError => e
      raise unless e.message["getaddrinfo: "]
    end
  end
  %w{
    http://www.aeronautica.difesa.it/organizzazione/REPARTI/divolo/PublishingImages/6%C2%B0%20Stormo/2013-decollo%20al%20tramonto%20REX%201280.jpg
  }.each do |url|   # TODO: test that setting user-agent header fixes this timeout
    begin
      fail NetHTTPUtils.request_data url, timeout: 5, max_read_retry_delay: -1
    rescue Net::ReadTimeout
    end
  end

  begin
    fail NetHTTPUtils.request_data "https://oi64.tinypic.com/29z7oxs.jpg?", timeout: 5, max_timeout_retry_delay: -1
  rescue Net::OpenTimeout => e
  end
  ## this stopped failing on High Sierra
  # begin
  #   # https://www.virtualself.co/?
  #   fail NetHTTPUtils.request_data "https://bulletinxp.com/curiosity/strange-weather/?", max_sslerror_retry_delay: -1
  # rescue OpenSSL::SSL::SSLError => e
  # end

  puts "OK #{__FILE__}"
end
