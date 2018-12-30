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
      str.gsub(/<script( [a-z]+="[^"]*")*>.*?<\/script>/m, "").
          gsub(/<style( [a-z]+="[^"]*")*>.*?<\/style>/m, "").
          gsub(/<[^>]*>/, "").split(?\n).map(&:strip).reject(&:empty?).join(?\n)
    end

    def start_http url, timeout = 30, max_start_http_retry_delay = 3600
      fail if url.is_a? URI::HTTP
      uri = url
      uri = URI.parse begin
        URI url
        url
      rescue URI::InvalidURIError
        URI.escape url
      end
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
        if max_start_http_retry_delay < delay *= 2
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
        if max_start_http_retry_delay < delay *= 2
          e.message.concat " to #{uri}"
          raise e
        end
        logger.warn "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{uri}"
        sleep delay
        retry
      rescue Errno::ETIMEDOUT, Net::OpenTimeout => e
        raise if max_start_http_retry_delay < delay *= 2
        logger.warn "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{uri}"
        sleep delay
        retry
      rescue OpenSSL::SSL::SSLError => e
        raise if max_start_http_retry_delay < delay *= 2
        logger.error "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{uri}"
        sleep delay
        retry
      end.tap do |http|
        http.instance_variable_set "@uri", uri
        http.define_singleton_method :read do |mtd = :GET, type = :form, form: {}, header: {}, auth: nil, timeout: 30,
            max_read_retry_delay: 3600,
            patch_request: nil,
            &block|

          logger = NetHTTPUtils.logger

          logger.warn "Warning: query params included in `url` argument are discarded because `:form` isn't empty" if uri.query && !form.empty?
          # we can't just merge because URI fails to parse such queries as "/?1"

          uri.query = URI.encode_www_form form if :GET == (mtd = mtd.upcase) && !form.empty?
          cookies = {}
          prepare_request = lambda do |uri, mtd = :GET, form = {}|
            case mtd.upcase
              when :GET    ; Net::HTTP::Get
              when :POST   ; Net::HTTP::Post
              when :PUT    ; Net::HTTP::Put
              when :DELETE ; Net::HTTP::Delete
              when :PATCH  ; Net::HTTP::Patch
              else         ; raise "unknown method '#{mtd}'"
            end.new(uri).tap do |request| # somehow Get eats even raw url, not URI object
              patch_request.call uri, form, request if patch_request
              # p Object.instance_method(:method).bind(request).call(:basic_auth).source_location
              # p Object.instance_method(:method).bind(request).call(:set_form).source_location
              # request.basic_auth *p(auth.map(&URI.method(:escape))) if auth
              request.basic_auth *auth if auth
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
              request["cookie"] = [*request["cookie"], cookies.map{ |k, v| "#{k}=#{v}" }].join "; " unless cookies.empty?

              logger.info "> #{request.class} #{uri.host} #{request.path}"
              next unless logger.debug?
              logger.debug "content-type: #{request.content_type}" unless mtd == :GET
              curl_form = case request.content_type
                when "application/json" ; "-d #{JSON.dump form} "
                when "multipart/form-data" ; form.map{ |k, v| "-F \"#{k}=#{v.respond_to?(:to_path) ? "@#{v.to_path}" : v}\" " }.join
                when "application/x-www-form-urlencoded" ; "-d \"#{URI.encode_www_form form}\" "
                else ; mtd == :GET ? "" : fail("unknown content-type '#{request.content_type}'")
              end
              logger.debug "curl -vsSL --compressed -o /dev/null #{
                request.each_header.map{ |k, v| "-H \"#{k}: #{v}\" " unless k == "host" }.join
              }#{curl_form}'#{url.gsub "&", "\\\\&"}#{"?#{uri.query}" if uri.query && uri.query.empty?}'"
              logger.debug "> header: #{request.each_header.to_a}"
              logger.debug "> body: #{request.body.inspect.tap{ |body| body[997..-1] = "..." if body.size > 500 }}"
              # TODO this is buggy -- mixes lines from different files into one line
              stack = caller.reverse.map do |level|
                /((?:[^\/:]+\/)?[^\/:]+):([^:]+)/.match(level).captures
              end.chunk(&:first).map do |file, group|
                "#{file}:#{group.map(&:last).chunk{|_|_}.map(&:first).join(",")}"
              end
              logger.debug stack.join " -> "
            end
          end
          http = NetHTTPUtils.start_http url, timeout, max_start_http_retry_delay
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

            remaining, reset_time, current_timestamp = if response.key? "x-ratelimit-userremaining"
              logger.debug "x-ratelimit-clientremaining: #{response.fetch("x-ratelimit-clientremaining").to_i}"
              [
                response.fetch("x-ratelimit-userremaining").to_i,
                response.fetch("x-ratelimit-userreset").to_i,
                response.fetch("x-timer")[/\d+/].to_i,
              ]
            elsif response.key? "x-rate-limit-remaining"
              [
                response.fetch("x-rate-limit-remaining").to_i,
                response.fetch("x-rate-limit-reset").to_i,
                Time.now.to_i,
              ]
            end
            if remaining
              logger.debug "x-remaining: #{remaining}"
              if remaining <= 100
                t = (reset_time - current_timestamp + 1).fdiv remaining
                logger.warn "x-ratelimit sleep #{t} seconds"
                sleep t
              end
            end

            response.to_hash.fetch("set-cookie", []).each do |c|
              k, v = c.split(?=)
              logger.debug "set-cookie: #{k}=#{v[/[^;]+/]}"
              cookies.store k, v[/[^;]+/]
            end
            logger.debug "< header: #{response.to_hash}"
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
                http = start_http new_uri, timeout, max_start_http_retry_delay
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
              logger.debug "< body: #{
                response.body.tap do |body|
                  body.replace remove_tags body if body[/<html[> ]/]
                end.inspect
              }"
              response
            end
          end
          do_request[prepare_request[uri, mtd, form]].tap do |response|
            cookies.each{ |k, v| response.add_field "Set-Cookie", "#{k}=#{v};" }
            logger.debug "< header: #{response.to_hash}"
          end.body

        end
      end
    end

    def request_data http, mtd = :GET, type = :form, form: {}, header: {}, auth: nil, timeout: 30,
        max_start_http_retry_delay: 3600,
        max_read_retry_delay: 3600,
        patch_request: nil, &block
      http = start_http http, timeout, max_start_http_retry_delay unless http.is_a? Net::HTTP
      path = http.instance_variable_get(:@uri).path
      head = http.head path
      raise Error.new(
        (head.to_hash["content-type"] == ["image/png"] ? head.to_hash["content-type"] : head.body),
        head.code.to_i
      ) unless head.code[/\A(20\d|3\d\d)\z/]
      body = http.read mtd, type, form: form, header: header, auth: auth, timeout: timeout,
        max_read_retry_delay: max_read_retry_delay,
        patch_request: patch_request, &block
      if head.to_hash["content-encoding"] == "gzip"
        Zlib::GzipReader.new(StringIO.new(body)).read
      else
        body
      end.tap do |string|
        string.instance_variable_set :@uri_path, path
        string.instance_variable_set :@header, head.to_hash
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
  Thread.abort_on_exception = true

  server = WEBrick::HTTPServer.new Port: 8000
  stack = []
  server.mount_proc ?/ do |req, res|
    stack.push req.request_method
  end
  Thread.new{ server.start }
  NetHTTPUtils.start_http("http://localhost:8000/")
  fail unless stack == %w{ }
  stack.clear
  NetHTTPUtils.start_http("http://localhost:8000/").head("/")
  fail unless stack == %w{ HEAD }
  stack.clear
  NetHTTPUtils.request_data("http://localhost:8000/")
  fail unless stack == %w{ HEAD GET }
  server.shutdown

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
  [400, 404, 500, 502, 503].each do |code|
    begin
      fail NetHTTPUtils.request_data "http://httpstat.us/#{code}"
    rescue NetHTTPUtils::Error => e
      raise unless e.code == code
    end
  end
  fail unless NetHTTPUtils.start_http("http://httpstat.us/400").read == "400 Bad Request"
  fail unless NetHTTPUtils.start_http("http://httpstat.us/404").read == "404 Not Found"
  fail unless NetHTTPUtils.start_http("http://httpstat.us/500").read == "500 Internal Server Error"
  fail unless NetHTTPUtils.start_http("http://httpstat.us/502").read == "502 Bad Gateway"
  fail unless NetHTTPUtils.start_http("http://httpstat.us/503").read == "503 Service Unavailable"
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
      fail NetHTTPUtils.request_data url, max_start_http_retry_delay: -1
    rescue SocketError => e
      raise unless e.message["getaddrinfo: "]
    end
  end
  %w{
    http://www.aeronautica.difesa.it/organizzazione/REPARTI/divolo/PublishingImages/6%C2%B0%20Stormo/2013-decollo%20al%20tramonto%20REX%201280.jpg
  }.each do |url|
    begin
      NetHTTPUtils.request_data url, timeout: 5, max_read_retry_delay: -1
      fail
    rescue Net::ReadTimeout
    end
  end

  begin
    fail NetHTTPUtils.request_data "https://oi64.tinypic.com/29z7oxs.jpg?", timeout: 5, max_start_http_retry_delay: -1
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
