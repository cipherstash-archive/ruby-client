require "net/http"

module CipherStash
  class Client
    # Convert an access key into an access token via Console.
    #
    # @private
    class ConsoleAccessKeyCredentials
      EXPIRY_GRACE_PERIOD_SECONDS = 30

      def initialize(profile, key, logger)
        @profile, @key, @logger = profile, key, logger
      end

      def fresh_credentials
        acquire_new_token

        return { access_token: @cached_token["accessToken"] }
      end

      def expired?
        @logger.debug("ConsoleAccessKeyCredentials#expired?") do
          @cached_token.nil? ?
            "No cached token" :
            (@cached_token["expiry"].nil? ?
              "No expiry on cached token" :
              "Cached token expires at #{@cached_token["expiry"]}, #{@cached_token["expiry"] - Time.now.to_i}s until expiry"
            )
        end
        @cached_token.nil? || @cached_token["expiry"].nil? || (Time.now.to_i + EXPIRY_GRACE_PERIOD_SECONDS > @cached_token["expiry"])
      end

      private

      def acquire_new_token
        res = post("/api/authorise", accessKey: @key)

        if res.code != "200"
          @logger.debug("ConsoleAccessKeyCredentials#acquire_new_token") { "Error response from console, HTTP #{res.code}, body: #{res.body.inspect}" }
          raise Error::AuthenticationFailure, "Unable to obtain access token from access key, IdP returned HTTP #{res.code}"
        end

        @cached_token = begin
                          JSON.parse(res.body)
                        rescue JSON::ParserError => ex
                          raise Error::AuthenticationFailure, "Unable to parse response from IdP: #{ex.message}"
                        end

        @logger.debug("ConsoleAccessKeyCredentials#acquire_new_token") { "Access token now expires at #{@cached_token["expiry"].inspect}" }
      end


      def post(path, data)
        @logger.debug("ConsoleAccessKeyCredentials") { "POST #{path} #{data.inspect}" }
        Net::HTTP.post(idp_uri(path), data.to_json, "Content-Type" => "application/json")
      end

      def idp_uri(path)
        @idp_uri_base ||= begin
                            idp_config = @profile.identity_provider_config
                            URI("https://#{idp_config["host"]}")
                          end

        @idp_uri_base.dup.tap { |u| u.path = path }
      end
    end
  end
end
