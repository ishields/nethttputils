require "net/http"
require "cgi"
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
    attr_reader :body
    def initialize body, code = nil
      @code = code
      @body = body
      body = body[0...997] + "..." if body.size > 1000
      super "HTTP error ##{code.inspect} #{body}"
    end
  end
  class EOFError_from_rbuf_fill < StandardError
  end

  class << self
    require "addressable"

    def remove_tags str
      str.gsub(/<script( [a-z-]+="[^"]*")*>.*?<\/script>/m, "").
          gsub(/<style( [a-z-]+="[^"]*")*>.*?<\/style>/m, "").
          gsub(/<[^>]*>/, "").split(?\n).map(&:strip).reject(&:empty?).join(?\n)
    end

    def start_http url, max_start_http_retry_delay = 3600, timeout = nil, no_redirect = false, proxy = nil
      timeout ||= 30
      uri = url

      uri = begin
        URI url
      rescue URI::InvalidURIError
        URI Addressable::URI.escape url
      end unless url.is_a? URI::HTTP
      raise Error, "can't parse host" unless uri.host

      delay = 5
      begin
        Net::HTTP.start(
          uri.host, uri.port,
          *(proxy.split ?: if proxy),
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
                @@buffer = @@buffer[0...997] + "..." if @@buffer.size > 1000
                return unless @@buffer.end_with? ?\n
                NetHTTPUtils.logger.debug @@buffer.sub ?\n, "  "
                @@buffer = nil
              end
            end
          end ) if logger.level == Logger::DEBUG # use `logger.debug?`?
          http
        end
      rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::ECONNRESET => e
        if max_start_http_retry_delay < delay *= 2
          e.message.concat " to #{uri}"
          raise
        end
        logger.warn "retrying in #{delay} seconds because of #{e.class} '#{e.message}'"
        sleep delay
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
        http.instance_variable_set :@uri, uri
        http.instance_variable_set :@max_start_http_retry_delay, max_start_http_retry_delay
      end
    end

    private
    def read http, mtd = :GET, type = :form, form: {}, header: {}, auth: nil, force_post: false, timeout: nil, no_redirect: false, max_read_retry_delay: 3600, patch_request: nil, &block
      timeout ||= 30
      logger = NetHTTPUtils.logger
      logger.info [mtd, http].inspect

          uri = http.instance_variable_get :@uri
      if %i{ HEAD GET }.include?(mtd = mtd.upcase) && !form.empty?  # not .upcase! because it's not defined for Symbol
        logger.debug "Warning: query params included in `url` argument are discarded because `:form` isn't empty" if uri.query
          # we can't just merge because URI fails to parse such queries as "/?1"
        uri.query = URI.encode_www_form form
      end
          cookies = {}
          prepare_request = lambda do |uri|
            case mtd.upcase
              when :HEAD   ; Net::HTTP::Head
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
                form.replace form.map{ |k, v| [k.to_s, v.is_a?(Integer) ? v.to_s : v] }.to_h
                case type
                  when :json
                                    request.body = JSON.dump form
                                    request.content_type = "application/json"
                  when :multipart   # in this case form can be of width 3 (when sending files)
                    request.set_form form, "multipart/form-data"
                  when :form
                               if form.any?{ |k, v| v.respond_to? :to_path }
                                 request.set_form form, "multipart/form-data"
                               else
                                 request.set_form_data form
                                 request.content_type = "application/x-www-form-urlencoded;charset=UTF-8"
                               end
                  else
                    raise "unknown content-type '#{type}'"
                end
              end
              header.each{ |k, v| request[k.to_s] = v.is_a?(Array) ? v.first : v }
              request["cookie"] = [*request["cookie"], cookies.map{ |k, v| "#{k}=#{v}" }].join "; " unless cookies.empty?

              logger.info "> #{request.class} #{uri.host} #{request.path}"
              next unless logger.debug?
              logger.debug "content-length: #{request.content_length.to_i}, content-type: #{request.content_type}" unless %i{ HEAD GET }.include? mtd
              logger.debug "query: #{uri.query.inspect}"
              logger.debug "content-type: #{request.content_type.inspect}"
              curl_form = case request.content_type
                when "application/json" ; "-d #{JSON.dump form} "
                when "multipart/form-data" ; form.map{ |k, v| "-F \"#{k}=#{v.respond_to?(:to_path) ? "@#{v.to_path}" : v}\" " }.join
                when "application/x-www-form-urlencoded" ; "-d \"#{URI.encode_www_form form}\" "
                else %i{ HEAD GET }.include?(mtd) ? "" : fail("unknown content-type '#{request.content_type}'")
              end
              logger.debug "curl -vsSL --compressed -o /dev/null #{"-X HEAD " if request.is_a? Net::HTTP::Head}#{
                request.each_header.map{ |k, v| "-H \"#{k}: #{v}\" " unless k == "host" }.join
              }#{curl_form}'#{uri.scheme}://#{uri.host}#{uri.path}#{"?#{uri.query}" if uri.query && !uri.query.empty?}'"
              logger.debug "> header: #{request.each_header.to_a}"
              logger.debug "> body: #{request.body.inspect.tap{ |body| body.replace body[0...997] + "..." if body.size > 1000 }}"
              # TODO this is buggy -- mixes lines from different files into one line
              stack = caller.reverse.map do |level|
                /((?:[^\/:]+\/)?[^\/:]+):([^:]+)/.match(level).captures
              end.chunk(&:first).map do |file, group|
                "#{file}:#{group.map(&:last).chunk{|_|_}.map(&:first).join(",")}"
              end
              logger.info stack.join " -> "
            end
          end
          do_request = lambda do |request|
            delay = 5
            response = begin
              http.request request, &block
            rescue Errno::ECONNREFUSED, Net::ReadTimeout, Net::OpenTimeout, Zlib::BufError, Errno::ECONNRESET, OpenSSL::SSL::SSLError, Errno::ETIMEDOUT, Errno::ENETUNREACH => e
              raise if max_read_retry_delay < delay *= 2
              logger.error "retrying in #{delay} seconds because of #{e.class} '#{e.message}' at: #{request.uri}"
              sleep delay
              retry
            rescue EOFError => e
              raise unless e.backtrace.empty?
              # https://bugs.ruby-lang.org/issues/13018
              # https://blog.kalina.tech/2019/04/exception-without-backtrace-in-ruby.html
              raise EOFError_from_rbuf_fill.new "probably the old Ruby empty backtrace EOFError exception from net/protocol.rb"
            end
            # response.instance_variable_set "@nethttputils_close", http.method(:finish)
            # response.singleton_class.instance_eval{ attr_accessor :nethttputils_socket_to_close }

            now = Time.now
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
                now.to_i,
              ]
            elsif response.key? "x-ratelimit-remaining"
              [
                response.fetch("x-ratelimit-remaining").to_i,
                now.to_i + response.fetch("x-ratelimit-reset").to_i,
                now.to_i,
              ]
            end
            if remaining
              logger.debug "x-remaining: #{remaining}"
              if remaining <= 100
                t = (reset_time - current_timestamp + 1).fdiv([remaining - 5, 1].max)
                logger.warn "x-ratelimit sleep #{t} seconds"
                sleep t
              end
            end

            # TODO: use WEBrick::Cookie
            old_cookies = cookies.dup
            response.to_hash.fetch("set-cookie", []).each do |c|
              next logger.warn "bad cookie: #{c.inspect}" unless /\A([^\s=]+)=([^\s]*)\z/.match c.split(/\s*;\s*/).first
              logger.debug "set-cookie: #{$1}=#{$2}"
              old_cookies.delete $1
              cookies.store $1, $2
            end
            old_cookies.each do |k, v|
              logger.debug "faking an old cookie into new response: #{k}=#{v}"
              response.add_field "Set-Cookie", "#{k}=#{v}"
            end

            logger.info "response.code = #{response.code}"
            case response.code
            when /\A20/
              response
            when /\A30\d\z/
              next response if no_redirect
              logger.info "redirect: #{response["location"]}"
              new_uri = URI.join request.uri.to_s, Addressable::URI.escape(response["location"])
              new_host = new_uri.host
              raise Error.new "redirected in place" if new_uri == http.instance_variable_get(:@uri)
              if http.address != new_host ||
                 http.port != new_uri.port ||
                 http.use_ssl? != (new_uri.scheme == "https")
                logger.debug "changing host from '#{http.address}' to '#{new_host}'"
                # http.finish   # why commented out?
                http = NetHTTPUtils.start_http new_uri, http.instance_variable_get(:@max_start_http_retry_delay), timeout, no_redirect
              end
              if !force_post && request.method == "POST"
                logger.info "POST redirects to GET (RFC)"   # TODO: do it only on code 307; note that some servers still do 302
                mtd = :GET
              end
              do_request.call prepare_request[new_uri]
            when "404"
              logger.error "404 at #{request.method} #{request.uri} with body: #{
                if !response.body
                  response.body.class
                elsif response.body.is_a? Net::ReadAdapter
                  "<<impossible to reread Net::ReadAdapter -- check the IO you've used in block form>>"
                elsif response.to_hash["content-type"] == ["image/png"]
                  response.to_hash["content-type"].to_s
                else
                  response.body.tap do |body|
                    body.replace NetHTTPUtils.remove_tags body if body[/<html[> ]/]
                  end.inspect
                end
              }"
              response
            when "429"
              logger.error "429 at #{request.method} #{request.uri} with body: #{response.body.inspect}"
              response
            when /\A50\d\z/
              logger.error "#{response.code} at #{request.method} #{request.uri} with body: #{
                if !response.body
                  response.body.class
                else
                  response.body.tap do |body|
                    body.replace NetHTTPUtils.remove_tags body if body[/<html[> ]/]
                  end.inspect
                end
              }"
              response
            else
              logger.warn "code #{response.code} from #{request.method} #{request.uri} at #{
                caller_path, caller_locs = caller_locations.chunk(&:path).first
                [caller_path, caller_locs.map(&:lineno).chunk(&:itself).map(&:first)].join ":"
              }"
              logger.debug "< body: #{
                response.body.tap do |body|
                  body.replace NetHTTPUtils.remove_tags body if body[/<html[> ]/]
                end.inspect
              }" if request.is_a? Net::HTTP::Get
              response
            end
          end
          response = do_request.call prepare_request[uri]
          logger.debug "< header: #{response.to_hash}"
          (response.body || "").tap{ |r| r.instance_variable_set :@last_response, response }
    end
    public

    require "set"
    @@_405 ||= Set.new
    def request_data http, mtd = :GET, type = :form, form: {}, header: {}, auth: nil, proxy: nil, force_post: false, no_redirect: false, head: false,
        timeout: nil, max_start_http_retry_delay: 3600, max_read_retry_delay: 3600,
        patch_request: nil, &block
      timeout ||= 30
      http = start_http http, max_start_http_retry_delay, timeout, no_redirect, *proxy unless http.is_a? Net::HTTP
      path = http.instance_variable_get(:@uri).path

      check_code = lambda do |body|
        fail unless code = body.instance_variable_get(:@last_response).code
        case code
          # TODO: raise on 405
          when /\A(20\d|3\d\d|405)\z/
            nil
          else
            ct = body.instance_variable_get(:@last_response).to_hash["content-type"]
            raise Error.new(
              (ct == ["image/png"] ? "<#{ct.first}>" : body),
              code.to_i
            )
        end
      end
      if head && mtd == :GET && !@@_405.include?(http.address)
        body = begin
          request_data http, :HEAD, form: form, header: header, auth: auth,
            max_start_http_retry_delay: max_start_http_retry_delay,
            max_read_retry_delay: max_read_retry_delay
        rescue NetHTTPUtils::Error => e
          raise unless e.code == 400
        end
        if !body || "405" == body.instance_variable_get(:@last_response).code
          @@_405.add http.address
        else
          check_code.call body
        end
      end
      body = read http, mtd, type, form: form, header: header, auth: auth, force_post: force_post,
        timeout: timeout, no_redirect: no_redirect,
        max_read_retry_delay: max_read_retry_delay,
        patch_request: patch_request, &block
      check_code.call body

      last_response = body.instance_variable_get :@last_response
      if last_response.to_hash["content-encoding"] == "gzip"
        Zlib::GzipReader.new(StringIO.new(body)).read
      else
        body
      end
    # ensure
    #   response.instance_variable_get("@nethttputils_close").call if response
    end

  end
end


if $0 == __FILE__
  STDOUT.sync = true
  print "self testing... "
  NetHTTPUtils.logger.level = Logger::DEBUG
  require "pp"

  NetHTTPUtils.request_data "https://goo.gl/ySqUb5"   # this will fail if domain redirects are broken

  require "webrick"
  require "json"
  Thread.abort_on_exception = true

  server = WEBrick::HTTPServer.new Port: 8000
  tt = false
  server.mount_proc "/" do |req, res|
    next unless "HEAD" == req.request_method
    fail if tt
    tt = true
    res.status = 300
    res["location"] = "/"
  end
  t = Thread.new{ server.start }
  begin
    NetHTTPUtils.request_data "http://localhost:8000/"
  rescue NetHTTPUtils::Error => e
    raise if e.code
  end
  server.shutdown
  t.join

  server = WEBrick::HTTPServer.new Port: 8000
  server.mount_proc "/1" do |req, res|
    next unless "GET" == req.request_method
    res.cookies.push WEBrick::Cookie.new "1", "2"
    res.cookies.push WEBrick::Cookie.new "3", "4"
    res.cookies.push WEBrick::Cookie.new "8", "9"
    res.cookies.push WEBrick::Cookie.new "a", "b"
    res.cookies.push WEBrick::Cookie.new "1", "5"
    res.cookies.push WEBrick::Cookie.new "f", "g h"
    res.status = 300
    res["location"] = "/2"
  end
  server.mount_proc "/2" do |req, res|
    res.cookies.push WEBrick::Cookie.new "3", "6=c"
    res.cookies.push WEBrick::Cookie.new "a", "d e"
    res.cookies.push WEBrick::Cookie.new "8", ""
    res.cookies.push WEBrick::Cookie.new "4", "7"
  end
  t = Thread.new{ server.start }
  fail unless %w{ 3=6=c a=d\ e 8= 4=7 1=5 a=b } == p(NetHTTPUtils.request_data("http://localhost:8000/1").
    instance_variable_get(:@last_response).to_hash.fetch("set-cookie"))
  server.shutdown
  t.join

  # HEAD should raise on 404 but not in two other cases
  [
    [WEBrick::HTTPStatus::NotFound, 404],
    [WEBrick::HTTPStatus::BadRequest],
    [WEBrick::HTTPStatus::MethodNotAllowed],
  ].each do |webrick_exception, should_raise|
    server = WEBrick::HTTPServer.new Port: 8000
    server.mount_proc ?/ do |req, res|
      res.set_error webrick_exception.new if "HEAD" == req.request_method
    end
    t = Thread.new{ server.start }
    begin
      NetHTTPUtils.request_data "http://localhost:8000/", head: true
      NetHTTPUtils.class_variable_get(:@@_405).clear
      fail if should_raise
    rescue NetHTTPUtils::Error => e
      fail unless 404 == e.code
    end
    server.shutdown
    t.join
  end

  server = WEBrick::HTTPServer.new Port: 8000
  stack = []
  server.mount_proc ?/ do |req, res|
    p stack.push req.request_method
  end
  t = Thread.new{ server.start }
  NetHTTPUtils.start_http("http://localhost:8000/")
  fail stack.inspect unless stack == %w{ }
  stack.clear
  NetHTTPUtils.start_http("http://localhost:8000/").head("/")
  fail stack.inspect unless stack == %w{ HEAD }
  stack.clear
  NetHTTPUtils.request_data("http://localhost:8000/", :head)
  fail stack.inspect unless stack == %w{ HEAD }
  stack.clear
  NetHTTPUtils.request_data("http://localhost:8000/", head: true)
  fail stack.inspect unless stack == %w{ HEAD GET }
  server.shutdown
  t.join

  # TODO: test that HEAD method request goes through redirects
  # TODO: test for `NetHTTPUtils.request_data "...", :head
  # TODO: request the HEAD only if mtd == :GET

  server = WEBrick::HTTPServer.new Port: 8000
  server.mount_proc ?/ do |req, res|
    # pp req.dup.tap{ |_| _.instance_variable_set "@config", nil }
    # res.status = WEBrick::HTTPStatus::RC_ACCEPTED
    res.body = JSON.dump [req.unparsed_uri, req.header.keys]
  end
  Thread.abort_on_exception = true
  Thread.new{ server.start }
  check = lambda do |path, headers, response|
    fail response unless JSON.dump([path, headers]) == response
  end
  check["/", %w{ accept-encoding accept user-agent host connection }, NetHTTPUtils.request_data("http://localhost:8000/")]
  check["/?1", %w{ accept-encoding accept user-agent host connection }, NetHTTPUtils.request_data("http://localhost:8000/?1")]
  check["/?1=2", %w{ accept-encoding accept user-agent host connection }, NetHTTPUtils.request_data("http://localhost:8000/?1=2")]
  check["/?1=3", %w{ accept-encoding accept user-agent host connection }, NetHTTPUtils.request_data("http://localhost:8000/?1=2&3=4", form: {1=>3})]
  check["/", %w{ accept-encoding accept user-agent host content-type connection content-length }, NetHTTPUtils.request_data("http://localhost:8000/", :post, form: {1=>2})]
  server.shutdown


  fail unless NetHTTPUtils.request_data("http://httpstat.us/200") == "200 OK"
  [400, 404, 500, 502, 503].each do |code|
    begin
      fail NetHTTPUtils.request_data "http://httpstat.us/#{code}"
    rescue NetHTTPUtils::Error => e
      raise unless e.code == code
    end
  end
  fail unless NetHTTPUtils.method(:read).call(NetHTTPUtils.start_http("http://httpstat.us/400")) == "400 Bad Request"
  fail unless NetHTTPUtils.method(:read).call(NetHTTPUtils.start_http("http://httpstat.us/404")) == "404 Not Found"
  fail unless NetHTTPUtils.method(:read).call(NetHTTPUtils.start_http("http://httpstat.us/500")) == "500 Internal Server Error"
  fail unless NetHTTPUtils.method(:read).call(NetHTTPUtils.start_http("http://httpstat.us/502")).start_with? "httpstat.us | 502: Bad gateway\nError\n502\n"
  fail unless NetHTTPUtils.method(:read).call(NetHTTPUtils.start_http("http://httpstat.us/503")) == "503 Service Unavailable"
  [
    # ["https://imgur.com/a/oacI3gl"],  # TODO: Imgur now hangs on these pages, I guess they had to be some 404 error page
    # ["https://imgur.com/mM4Dh7Z"],    # TODO: Imgur now hangs on these pages, I guess they had to be some 404 error page
    ["https://i.redd.it/si758zk7r5xz.jpg", "HTTP error #404 <image/png>"],
  ].each do |url, expectation|
    begin
      puts NetHTTPUtils.remove_tags NetHTTPUtils.request_data url
      fail url
    rescue NetHTTPUtils::Error => e
      raise e.code.inspect unless e.code == 404
      raise e.to_s if e.to_s != expectation if expectation
    end
  end
  %w{
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
      NetHTTPUtils.request_data url, timeout: 5, max_read_retry_delay: -1, head: true
      fail
    rescue Net::ReadTimeout
    end
  end

  ## this stopped failing on High Sierra
  # begin
  #   # https://www.virtualself.co/?
  #   fail NetHTTPUtils.request_data "https://bulletinxp.com/curiosity/strange-weather/?", max_sslerror_retry_delay: -1
  # rescue OpenSSL::SSL::SSLError => e
  # end

  puts "OK #{__FILE__}"
end
