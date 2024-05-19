require 'json'
require 'securerandom'
require 'digest'
require 'openssl'

module FadadaRubySdk
  # To sign client request message and verify tonglian's response message
  class Signer
    HEADER_STUB = {
      'X-FASC-Api-SubVersion' => 5.1,
      'X-FASC-Sign-Type' => 'HMAC-SHA256'
    }.freeze

    def initialize(app_id, app_secret)
      @app_id = app_id
      @app_secret = app_secret
    end

    def sign(access_token = nil, data={})
      headers, params = generate_headers_params(access_token, data)
      sign_string = make_sign_string(headers.merge(params))

      timestamp = headers['X-FASC-Timestamp']
      signature = generate_signature(sign_string, timestamp, @app_secret)
      headers['X-FASC-Sign'] = signature
      return headers, params
    end

    private

    def generate_headers_params(access_token, data)
      headers = HEADER_STUB.dup
      params = {}

      headers['X-FASC-App-Id'] = @app_id
      headers['X-FASC-Timestamp'] = (Time.now.to_f * 1000).to_i.to_s
      headers['X-FASC-Nonce'] = SecureRandom.uuid.gsub('-', '')
      if access_token.nil? || access_token.empty?
        headers['X-FASC-Grant-Type'] = 'client_credential'
      else
        headers['X-FASC-AccessToken'] = access_token
      end

      unless data.nil? || data.empty?
        params['bizContent'] = (data.is_a? String)? data : data.to_json
      end

      return headers, params
    end

    def make_sign_string(params)
      sorted_params = []
      params.keys.sort.map do |k|
        sorted_params.push("#{k}=#{params[k]}")
      end
      sorted_params.join('&')
    end

    def generate_signature(sorted_params_str, timestamp, secret)
      sorted_str_digest = Digest::SHA256.hexdigest(sorted_params_str)
      hmac = OpenSSL::HMAC.digest('sha256', secret, timestamp)
      OpenSSL::HMAC.hexdigest('sha256', hmac, sorted_str_digest)
    end
  end
end
