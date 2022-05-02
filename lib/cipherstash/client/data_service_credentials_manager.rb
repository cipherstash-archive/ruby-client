module CipherStash
  class Client
    # Responsible for making sure we always have fresh credz
    #
    # @private
    class DataServiceCredentialsManager
      EXPIRY_GRACE_PERIOD_SECONDS = 120

      def initialize(profile, logger)
        @profile, @logger = profile, logger
        @idp_config = @profile.identity_provider_config
      end

      def fresh_credentials
        # Hard-coded token isn't great, but it's easy if it works!
        unless (token = @idp_config["accessToken"]).nil?
          return { access_token: token }
        end

        if @cached_token.nil?
          read_cached_token
        end

        # No automatic refresh of tokens for now; need to use `stash login`
        return { access_token: @cached_token["accessToken"] }
      end

      def expired?
        if @cached_token.nil?
          read_cached_token
        end

        @cached_token && @cached_token["expiry"] && Time.now.to_i + EXPIRY_GRACE_PERIOD_SECONDS < @cached_token["expiry"]
      end

      private

      def read_cached_token
        @cached_token = @profile.read_cached_token
      end
    end
  end
end
