module JWTSessions
  module RailsAuthorization
    include Authorization

    def request_headers
      ActionDispatch::Http::Headers.from_hash(request.headers)
    end

    def request_cookies
      request.cookie_jar
    end

    def request_method
      request.method
    end
  end
end
