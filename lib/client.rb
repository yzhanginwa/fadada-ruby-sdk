require 'net/http'

module FadadaRubySdk
  # Client class to handle request and responses to and from Tonglian gateway
  class Client
    def initialize(api_end_point, app_id, app_secret)
      @api_end_point = api_end_point
      @signer = Signer.new(app_id, app_secret)
    end

    # the url is relative to the api_end_point
    def request(url, access_token, params)
      headers, params = @signer.sign(access_token, params)

      url = URI("#{@api_end_point}#{url}")
      http = Net::HTTP.new(url.host, url.port)
      http.use_ssl = true if @api_end_point.downcase.start_with?('https') # Enable SSL for HTTPS

      request = Net::HTTP::Post.new(url.request_uri)
      request['Content-Type'] = 'application/x-www-form-urlencoded'
      headers.each do |key, value|
        request[key] = value
      end

      request.body = URI.encode_www_form(params)
      response = http.request(request)

      JSON.parse(response.body)
    end
  end
end
