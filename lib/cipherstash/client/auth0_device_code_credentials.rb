module CipherStash
  class Client
    # Responsible for hassling Auth0 via device code auth when we need to get a fresh access token
    #
    # @private
    class Auth0DeviceCodeCredentials
      EXPIRY_GRACE_PERIOD_SECONDS = 120

      def initialize(profile, cached_token, logger)
        @profile, @cached_token, @logger = profile, cached_token, logger
      end

      def fresh_credentials
        # The cached token read off disk might still be perfectly fine!
        if expired?
          @logger.debug("Auth0DeviceCodeCredentials#fresh_credentials") { "cached credentials are stale" }
          acquire_new_token
        end

        @logger.debug("Auth0DeviceCodeCredentials#fresh_credentials") { "returning token" }

        return { access_token: @cached_token["accessToken"] }
      end

      def expired?
        @logger.debug("Auth0DeviceCodeCredentials#expired?") do
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
        if token = try_using_refresh_token
          @cached_token = token
          @profile.cache_access_token(@cached_token)
          return
        end

        polling_info = get_device_code_polling_info

        prompt_user(polling_info)

        @cached_token = poll_for_access_token(polling_info)
        @logger.debug("Auth0DeviceCodeCredentials#acquire_new_token") { "Access token now expires at #{@cached_token["expiry"].inspect}" }
        @profile.cache_access_token(@cached_token)
      end

      def try_using_refresh_token
        if @cached_token && @cached_token["refreshToken"]
          res = post(
            "/oauth/token",
            grant_type: "refresh_token",
            refresh_token: @cached_token["refreshToken"],
            client_id: idp_client_id
          )

          if res.code == "200"
            @logger.debug("Auth0DeviceCodeCredentials#try_using_refresh_token") { "Seems like the refresh token worked" }

            begin
              t = JSON.parse(res.body, symbolize_names: true)
              @cached_token = { "accessToken" => t[:access_token], "refreshToken" => t[:refresh_token], "expiry" => Time.now.to_i + t[:expires_in] }
            rescue => ex
              @logger.debug("Auth0DeviceCodeCredentials") { "Response body from /oauth/token: #{res.body.inspect}" }
              raise Error::AuthenticationFailure, "Failed to parse response body from /oauth/token: #{ex.message}"
            end
          else
            @logger.debug("Auth0DeviceCodeCredentials#try_using_refresh_token") { "Refresh token h0rked; HTTP #{res.code}, #{res.body.inspect}" }
          end
        end
      end

      def get_device_code_polling_info
        res = post(
          "/oauth/device/code",
          audience: idp_audience,
          client_id: idp_client_id,
          scope: idp_scopes.join(" ")
        )

        if res.code != "200"
          @logger.debug("Auth0DeviceCodeCredentials") { "Response body from /oauth/device/code: #{res.body.inspect}" }
          raise Error::AuthenticationFailure, "/oauth/device/code returned HTTP #{res.code}"
        end

        begin
          JSON.parse(res.body, symbolize_names: true)
        rescue => ex
          @logger.debug("Auth0DeviceCodeCredentials") { "Response body from /oauth/device/code: #{res.body.inspect}" }
          raise Error::AuthenticationFailure, "Failed to parse response body from /oauth/device/code: #{ex.message}"
        end
      end

      def prompt_user(polling_info)
        code = polling_info[:user_code]

        puts <<~EOF
          Visit #{polling_info[:verification_uri_complete]} to complete authentication by following the below steps:

          1. Verify that this code matches the code in your browser

                        +------#{'-' * code.length}------+
                        |      #{' ' * code.length}      |
                        |      #{      code       }      |
                        |      #{' ' * code.length}      |
                        +------#{'-' * code.length}------+

          2. If the codes match, click on the confirm button in the browser

          Waiting for authentication...
        EOF
      end

      def poll_for_access_token(polling_info)
        interval = 5

        loop do
          res = post(
            "/oauth/token",
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: polling_info[:device_code],
            client_id: idp_client_id
          )

          case res.code
          when "200"
            begin
              t = JSON.parse(res.body, symbolize_names: true)
              return { "accessToken" => t[:access_token], "refreshToken" => t[:refresh_token], "expiry" => Time.now.to_i + t[:expires_in] }
            rescue => ex
              @logger.debug("Auth0DeviceCodeCredentials") { "Response body from /oauth/token: #{res.body.inspect}" }
              raise Error::AuthenticationFailure, "Failed to parse response body from /oauth/token: #{ex.message}"
            end
          when "403"
            begin
              err = JSON.parse(res.body, symbolize_names: true)
              case err[:error]
              when "authorization_pending"
                @logger.debug("Auth0DeviceCodeCredentials") { "Still waiting for token" }
              when "slow_down"
                interval += 5
              when "invalid_grant"
                raise Error::AuthenticationFailure, "Device code authentication failed: #{err[:error_description].inspect}"
              else
                raise Error::AuthenticationFailure, "Failure while polling for access token: #{err.inspect}"
              end
            rescue JSON::ParserError => ex
              @logger.debug("Auth0DeviceCodeCredentials") { "Response body from /oauth/token: #{res.body.inspect}" }
              raise Error::AuthenticationFailure, "Failed to parse response body from /oauth/token: #{ex.message}"
            end
          else
            @logger.debug("Auth0DeviceCodeCredentials") { "Response body from /oauth/token: #{res.body.inspect}" }
            raise Error::AuthenticationFailure, "/oauth/token returned HTTP #{res.code}"
          end

          sleep interval
        end
      end

      def post(path, data)
        @logger.debug("Auth0DeviceCodeCredentials") { "POST #{path} #{data.inspect}" }
        Net::HTTP.post(idp_uri(path), data.to_json, "Content-Type" => "application/json")
      end

      def idp_uri(path)
        @idp_uri_base ||= begin
                            idp_config = @profile.identity_provider_config
                            URI("https://#{idp_config["host"]}")
                          end

        @idp_uri_base.dup.tap { |u| u.path = path }
      end

      def idp_audience
        @profile.service_host
      end

      def idp_client_id
        @profile.identity_provider_config["clientId"]
      end

      def idp_scopes
        %w{
          collection.create
          collection.delete
          collection.info
          collection.list
          document.put
          document.delete
          document.get
          document.query
          offline_access
        } + ["ws:#{@profile.workspace}"]
      end
    end
  end
end
